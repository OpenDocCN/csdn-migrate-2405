# C++ 游戏开发秘籍（四）

> 原文：[`zh.annas-archive.org/md5/260E2BE0C3FA0FF74505C2A10CA40511`](https://zh.annas-archive.org/md5/260E2BE0C3FA0FF74505C2A10CA40511)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：游戏开发中的物理

在本章中，将介绍以下食谱：

+   在游戏中使用物理规则

+   使物体发生碰撞

+   安装和集成 Box2D

+   制作基本的 2D 游戏

+   制作 3D 游戏

+   创建一个粒子系统

+   在游戏中使用布娃娃

# 介绍

在现代游戏和过去的游戏中，总是添加了某种类型的物理以增加现实感。尽管游戏中的大多数物理是对实际物理规则的近似或优化，但它确实很好地实现了期望的结果。游戏中的物理基本上是牛顿运动定律的粗略实现，结合了基本的碰撞检测原理。

游戏开发者的诀窍是以这样一种方式编写代码，使其不会成为 CPU 的瓶颈，游戏仍然以期望的框架运行。我们将讨论一些我们需要引入物理到游戏中的基本概念。为了简单起见，我们已经将**Box2D**集成到我们的引擎中，并且与渲染器（**OpenGL**）一起，我们将输出物体之间的一些物理交互。对于 3D 物理，我们将从**Bullet Physics** SDK 获得帮助，并显示期望的结果。

# 在游戏中使用物理规则

在游戏中引入物理的第一步是准备好环境，以便可以对物体应用适当的计算，并且物理模拟可以对其进行操作。

## 做好准备

要完成这个食谱，您需要一台运行 Windows 和 Visual Studio 的计算机。不需要其他先决条件。

## 如何做...

在这个食谱中，我们将看到向游戏中添加物理规则是多么容易：

1.  首先，在游戏场景中设置所有物体。

1.  给它们属性，使它们具有矢量点和速度。

1.  根据物体的形状分配边界框或边界圆。

1.  对每个物体施加力。

1.  根据形状检测它们之间的碰撞。

1.  解决约束。

1.  输出结果。

看一下以下代码片段：

```cpp
#include <Box2D/Collision/b2Collision.h>
#include <Box2D/Collision/Shapes/b2CircleShape.h>
#include <Box2D/Collision/Shapes/b2PolygonShape.h>

void b2CollideCircles(
  b2Manifold* manifold,
  const b2CircleShape* circleA, const b2Transform& xfA,
  const b2CircleShape* circleB, const b2Transform& xfB)
{
  manifold->pointCount = 0;

  b2Vec2 pA = b2Mul(xfA, circleA->m_p);
  b2Vec2 pB = b2Mul(xfB, circleB->m_p);

  b2Vec2 d = pB - pA;
  float32 distSqr = b2Dot(d, d);
  float32 rA = circleA->m_radius, rB = circleB->m_radius;
  float32 radius = rA + rB;
  if (distSqr > radius * radius)
  {
    return;
  }

  manifold->type = b2Manifold::e_circles;
  manifold->localPoint = circleA->m_p;
  manifold->localNormal.SetZero();
  manifold->pointCount = 1;

  manifold->points[0].localPoint = circleB->m_p;
  manifold->points[0].id.key = 0;
}

void b2CollidePolygonAndCircle(
  b2Manifold* manifold,
  const b2PolygonShape* polygonA, const b2Transform& xfA,
  const b2CircleShape* circleB, const b2Transform& xfB)
{
  manifold->pointCount = 0;

  // Compute circle position in the frame of the polygon.
  b2Vec2 c = b2Mul(xfB, circleB->m_p);
  b2Vec2 cLocal = b2MulT(xfA, c);

  // Find the min separating edge.
  int32 normalIndex = 0;
  float32 separation = -b2_maxFloat;
  float32 radius = polygonA->m_radius + circleB->m_radius;
  int32 vertexCount = polygonA->m_count;
  const b2Vec2* vertices = polygonA->m_vertices;
  const b2Vec2* normals = polygonA->m_normals;

  for (int32 i = 0; i < vertexCount; ++i)
  {
    float32 s = b2Dot(normals[i], cLocal - vertices[i]);

    if (s > radius)
    {
      // Early out.
      return;
    }

    if (s > separation)
    {
      separation = s;
      normalIndex = i;
    }
  }

  // Vertices that subtend the incident face.
  int32 vertIndex1 = normalIndex;
  int32 vertIndex2 = vertIndex1 + 1 < vertexCount ? vertIndex1 + 1 : 0;
  b2Vec2 v1 = vertices[vertIndex1];
  b2Vec2 v2 = vertices[vertIndex2];

  // If the center is inside the polygon ...
  if (separation < b2_epsilon)
  {
    manifold->pointCount = 1;
    manifold->type = b2Manifold::e_faceA;
    manifold->localNormal = normals[normalIndex];
    manifold->localPoint = 0.5f * (v1 + v2);
    manifold->points[0].localPoint = circleB->m_p;
    manifold->points[0].id.key = 0;
    return;
  }

  // Compute barycentric coordinates
  float32 u1 = b2Dot(cLocal - v1, v2 - v1);
  float32 u2 = b2Dot(cLocal - v2, v1 - v2);
  if (u1 <= 0.0f)
  {
    if (b2DistanceSquared(cLocal, v1) > radius * radius)
    {
      return;
    }

    manifold->pointCount = 1;
    manifold->type = b2Manifold::e_faceA;
    manifold->localNormal = cLocal - v1;
    manifold->localNormal.Normalize();
    manifold->localPoint = v1;
    manifold->points[0].localPoint = circleB->m_p;
    manifold->points[0].id.key = 0;
  }
  else if (u2 <= 0.0f)
  {
    if (b2DistanceSquared(cLocal, v2) > radius * radius)
    {
      return;
    }

    manifold->pointCount = 1;
    manifold->type = b2Manifold::e_faceA;
    manifold->localNormal = cLocal - v2;
    manifold->localNormal.Normalize();
    manifold->localPoint = v2;
    manifold->points[0].localPoint = circleB->m_p;
    manifold->points[0].id.key = 0;
  }
  else
  {
    b2Vec2 faceCenter = 0.5f * (v1 + v2);
    float32 separation = b2Dot(cLocal - faceCenter, normals[vertIndex1]);
    if (separation > radius)
    {
      return;
    }

    manifold->pointCount = 1;
    manifold->type = b2Manifold::e_faceA;
    manifold->localNormal = normals[vertIndex1];
    manifold->localPoint = faceCenter;
    manifold->points[0].localPoint = circleB->m_p;
    manifold->points[0].id.key = 0;
  }
}
```

## 它是如何工作的...

身体展现物理属性的第一步是成为刚体。然而，如果您的身体应该具有某种流体物理特性，比如塑料或其他软体，这就不成立了。在这种情况下，我们将不得不以不同的方式设置世界，因为这是一个更加复杂的问题。简而言之，刚体是世界空间中的任何物体，即使外部力作用于它，它也不会变形。即使在 Unity 或 UE4 等游戏引擎中，如果将一个物体分配为刚体，它也会根据引擎的物理模拟属性自动反应。设置好刚体后，我们需要确定物体是静态的还是动态的。这一步很重要，因为如果我们知道物体是静态的，我们可以大大减少计算量。动态物体必须分配速度和矢量位置。

在完成上一步之后，下一步是添加碰撞器或边界对象。这些实际上将用于计算碰撞点。例如，如果我们有一个人的 3D 模型，有时使用精确的身体网格进行碰撞并不明智。相反，我们可以使用一个胶囊，它是一个在身体两端各有两个半球的圆柱体，手部也有类似的结构。对于 2D 物体，我们可以在圆形边界对象或矩形边界对象之间做出选择。以下图表显示了物体为黑色，边界框为红色。现在我们可以对物体施加力或冲量：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/4929_09_01.jpg)

管道中的下一步是实际检测两个物体何时发生碰撞。我们将在下一个步骤中进一步讨论这个问题。但是假设我们需要检测`圆 A`是否与`圆 B`发生了碰撞；在大多数情况下，我们只需要知道它们是否发生了碰撞，而不需要知道具体的接触点。在这种情况下，我们需要编写一些数学函数来检测。然后我们返回输出，并根据此编写我们的碰撞逻辑，最后显示结果。

在前面的例子中，有一个名为`b2CollidePolygonAndCircle`的函数，用于计算多边形和圆之间的碰撞。我们定义了两个形状，然后尝试计算确定多边形和圆的点是否相交的各种细节。我们需要找到边缘列表点，然后计算这些点是否在另一个形状内部，依此类推。

# 使物体发生碰撞

物理系统的一个重要部分是使物体发生碰撞。我们需要弄清楚物体是否发生了碰撞，并传递相关信息。在这个步骤中，我们将看看不同的技术来做到这一点。

## 准备工作

你需要一台运行正常的 Windows 机器和一个可用的 Visual Studio 副本。不需要其他先决条件。

## 如何做…

在这个步骤中，我们将找出检测碰撞有多容易：

```cpp
#include <Box2D/Collision/b2Collision.h>
#include <Box2D/Collision/Shapes/b2PolygonShape.h>

// Find the max separation between poly1 and poly2 using edge normals from poly1.
static float32 b2FindMaxSeparation(int32* edgeIndex,
             const b2PolygonShape* poly1, const b2Transform& xf1,
             const b2PolygonShape* poly2, const b2Transform& xf2)
{
  int32 count1 = poly1->m_count;
  int32 count2 = poly2->m_count;
  const b2Vec2* n1s = poly1->m_normals;
  const b2Vec2* v1s = poly1->m_vertices;
  const b2Vec2* v2s = poly2->m_vertices;
  b2Transform xf = b2MulT(xf2, xf1);

  int32 bestIndex = 0;
  float32 maxSeparation = -b2_maxFloat;
  for (int32 i = 0; i < count1; ++i)
  {
    // Get poly1 normal in frame2.
    b2Vec2 n = b2Mul(xf.q, n1s[i]);
    b2Vec2 v1 = b2Mul(xf, v1s[i]);

    // Find deepest point for normal i.
    float32 si = b2_maxFloat;
    for (int32 j = 0; j < count2; ++j)
    {
      float32 sij = b2Dot(n, v2s[j] - v1);
      if (sij < si)
      {
        si = sij;
      }
    }

    if (si > maxSeparation)
    {
      maxSeparation = si;
      bestIndex = i;
    }
  }

  *edgeIndex = bestIndex;
  return maxSeparation;
}

static void b2FindIncidentEdge(b2ClipVertex c[2],
           const b2PolygonShape* poly1, const b2Transform& xf1, int32 edge1,
           const b2PolygonShape* poly2, const b2Transform& xf2)
{
  const b2Vec2* normals1 = poly1->m_normals;

  int32 count2 = poly2->m_count;
  const b2Vec2* vertices2 = poly2->m_vertices;
  const b2Vec2* normals2 = poly2->m_normals;

  b2Assert(0 <= edge1 && edge1 < poly1->m_count);

  // Get the normal of the reference edge in poly2's frame.
  b2Vec2 normal1 = b2MulT(xf2.q, b2Mul(xf1.q, normals1[edge1]));

  // Find the incident edge on poly2.
  int32 index = 0;
  float32 minDot = b2_maxFloat;
  for (int32 i = 0; i < count2; ++i)
  {
    float32 dot = b2Dot(normal1, normals2[i]);
    if (dot < minDot)
    {
      minDot = dot;
      index = i;
    }
  }

  // Build the clip vertices for the incident edge.
  int32 i1 = index;
  int32 i2 = i1 + 1 < count2 ? i1 + 1 : 0;

  c[0].v = b2Mul(xf2, vertices2[i1]);
  c[0].id.cf.indexA = (uint8)edge1;
  c[0].id.cf.indexB = (uint8)i1;
  c[0].id.cf.typeA = b2ContactFeature::e_face;
  c[0].id.cf.typeB = b2ContactFeature::e_vertex;

  c[1].v = b2Mul(xf2, vertices2[i2]);
  c[1].id.cf.indexA = (uint8)edge1;
  c[1].id.cf.indexB = (uint8)i2;
  c[1].id.cf.typeA = b2ContactFeature::e_face;
  c[1].id.cf.typeB = b2ContactFeature::e_vertex;
}

// Find edge normal of max separation on A - return if separating axis is found
// Find edge normal of max separation on B - return if separation axis is found
// Choose reference edge as min(minA, minB)
// Find incident edge
// Clip

// The normal points from 1 to 2
void b2CollidePolygons(b2Manifold* manifold,
            const b2PolygonShape* polyA, const b2Transform& xfA,
            const b2PolygonShape* polyB, const b2Transform& xfB)
{
  manifold->pointCount = 0;
  float32 totalRadius = polyA->m_radius + polyB->m_radius;

  int32 edgeA = 0;
  float32 separationA = b2FindMaxSeparation(&edgeA, polyA, xfA, polyB, xfB);
  if (separationA > totalRadius)
    return;

  int32 edgeB = 0;
  float32 separationB = b2FindMaxSeparation(&edgeB, polyB, xfB, polyA, xfA);
  if (separationB > totalRadius)
    return;

  const b2PolygonShape* poly1;  // reference polygon
  const b2PolygonShape* poly2;  // incident polygon
  b2Transform xf1, xf2;
  int32 edge1;          // reference edge
  uint8 flip;
  const float32 k_tol = 0.1f * b2_linearSlop;

  if (separationB > separationA + k_tol)
  {
    poly1 = polyB;
    poly2 = polyA;
    xf1 = xfB;
    xf2 = xfA;
    edge1 = edgeB;
    manifold->type = b2Manifold::e_faceB;
    flip = 1;
  }
  else
  {
    poly1 = polyA;
    poly2 = polyB;
    xf1 = xfA;
    xf2 = xfB;
    edge1 = edgeA;
    manifold->type = b2Manifold::e_faceA;
    flip = 0;
  }

  b2ClipVertex incidentEdge[2];
  b2FindIncidentEdge(incidentEdge, poly1, xf1, edge1, poly2, xf2);

  int32 count1 = poly1->m_count;
  const b2Vec2* vertices1 = poly1->m_vertices;

  int32 iv1 = edge1;
  int32 iv2 = edge1 + 1 < count1 ? edge1 + 1 : 0;

  b2Vec2 v11 = vertices1[iv1];
  b2Vec2 v12 = vertices1[iv2];

  b2Vec2 localTangent = v12 - v11;
  localTangent.Normalize();

  b2Vec2 localNormal = b2Cross(localTangent, 1.0f);
  b2Vec2 planePoint = 0.5f * (v11 + v12);

  b2Vec2 tangent = b2Mul(xf1.q, localTangent);
  b2Vec2 normal = b2Cross(tangent, 1.0f);

  v11 = b2Mul(xf1, v11);
  v12 = b2Mul(xf1, v12);

  // Face offset.
  float32 frontOffset = b2Dot(normal, v11);

  // Side offsets, extended by polytope skin thickness.
  float32 sideOffset1 = -b2Dot(tangent, v11) + totalRadius;
  float32 sideOffset2 = b2Dot(tangent, v12) + totalRadius;

  // Clip incident edge against extruded edge1 side edges.
  b2ClipVertex clipPoints1[2];
  b2ClipVertex clipPoints2[2];
  int np;

  // Clip to box side 1
  np = b2ClipSegmentToLine(clipPoints1, incidentEdge, -tangent, sideOffset1, iv1);

  if (np < 2)
    return;

  // Clip to negative box side 1
  np = b2ClipSegmentToLine(clipPoints2, clipPoints1,  tangent, sideOffset2, iv2);

  if (np < 2)
  {
    return;
  }

  // Now clipPoints2 contains the clipped points.
  manifold->localNormal = localNormal;
  manifold->localPoint = planePoint;

  int32 pointCount = 0;
  for (int32 i = 0; i < b2_maxManifoldPoints; ++i)
  {
    float32 separation = b2Dot(normal, clipPoints2[i].v) - frontOffset;

    if (separation <= totalRadius)
    {
      b2ManifoldPoint* cp = manifold->points + pointCount;
      cp->localPoint = b2MulT(xf2, clipPoints2[i].v);
      cp->id = clipPoints2[i].id;
      if (flip)
      {
        // Swap features
        b2ContactFeature cf = cp->id.cf;
        cp->id.cf.indexA = cf.indexB;
        cp->id.cf.indexB = cf.indexA;
        cp->id.cf.typeA = cf.typeB;
        cp->id.cf.typeB = cf.typeA;
      }
      ++pointCount;
    }
  }

  manifold->pointCount = pointCount;
}
```

## 工作原理…

假设场景中的物体已经设置为刚体，并且为每个物体添加了适当的冲量，下一步是检测碰撞。冲量是作用在物体上的力。这种力短暂地作用在物体上，并导致动量的一些变化。

在游戏中，碰撞检测通常分为两个阶段。第一阶段称为**广相碰撞**，下一阶段称为**窄相碰撞**。广相阶段成本较低，因为它处理的是哪些物体最有可能发生碰撞的概念。窄相阶段成本更高，因为它实际上比较了每个物体是否发生碰撞。在游戏环境中，不可能将所有内容都放在窄相阶段。因此，大部分工作都是在广相阶段完成的。广相算法使用扫描和修剪（排序和修剪）或空间分区树。在扫描和修剪技术中，对实体的边界框的所有下端和上端进行排序并检查是否相交。之后，它被发送到窄相阶段进行更详细的检查。因此，在这种方法中，我们需要在实体改变方向时更新其边界框。另一种使用的技术是**BSP**。我们已经在之前的章节中讨论过 BSP。我们需要将场景分割成这样的方式，使得在每个子分区中，只有一定数量的物体可以发生碰撞。在窄相碰撞中，会应用更像素完美的碰撞检测算法。

有各种方法来检查碰撞。这完全取决于充当边界框的形状。此外，了解边界框的对齐方式也很重要。在正常情况下，边界框将是轴对齐的，并且将被称为`AABB`。要检测两个 Box2D 边界框是否发生碰撞，我们需要执行以下操作：

```cpp
bool BoxesIntersect(const Box2D &a, const Box2D &b)
{
    if (a.max.x < b.min.x) return false; // a is left of b
    if (a.min.x > b.max.x) return false; // a is right of b
    if (a.max.y < b.min.y) return false; // a is above b
    if (a.min.y > b.max.y) return false; // a is below b
    return true; // boxes overlap
}
```

然后我们可以扩展这一点，以检测更复杂的形状，如矩形、圆形、线条和其他多边形。如果我们正在编写自己的 2D 物理引擎，那么我们将不得不为每种形状相互交叉编写一个函数。如果我们使用诸如 Box2D 或 PhysX 之类的物理引擎，这些函数已经被写好，我们只需要正确和一致地使用它们。

# 安装和集成 Box2D

要能够使用 2D 物理，一个很好的开源物理引擎是 Box2D。这个引擎带有许多对于任何 2D 游戏都常见的函数，因此我们不必重新发明轮子并重新编写它们。

## 准备工作

你需要有一台运行正常的 Windows 机器。

## 如何做…

按照以下步骤进行：

1.  转到[`box2d.org/`](http://box2d.org/)。

1.  浏览到[`box2d.org/downloads/`](http://box2d.org/downloads/)。

1.  从 GitHub 下载或克隆最新版本。

1.  在您的 Visual Studio 版本中构建解决方案。一些项目可能无法工作，因为它们是在不同版本的 Visual Studio 中构建的。

1.  如果出现错误，请清理解决方案，删除`bin`文件夹，然后重新构建它。

1.  解决方案成功重建后，运行`TestBed`项目。

1.  如果您能成功运行应用程序，Box2D 已经集成。

## 工作原理…

Box2D 是一个完全由 C++构建的物理引擎。由于它给了我们访问源代码的权限，这意味着我们也可以从头开始构建它，并检查每个函数是如何编写的。由于该项目托管在 GitHub 上，每次进行新开发时，我们都可以克隆它并更新所有最新的代码。

在解决方案中，Box2D 已经有一个名为`TestBed`的项目，其中包含许多可以运行的示例应用程序。实际上，这是许多不同类型应用程序的集合。`Test Entries`是所有应用程序的入口点。它是一个包含我们想要在`TestBed`项目中呈现的不同应用程序的长数组。该数组包含应用程序的名称和初始化世界的静态函数。

最后，物理模拟的输出被馈送到渲染器，这种情况下是 OpenGL，并为我们绘制场景。

# 制作基本的 2D 游戏

每个 2D 游戏都是不同的。然而，我们可以概括将在大多数 2D 游戏中使用的物理函数。在这个教程中，我们将使用 Box2D 的内置函数和`TestBed`项目创建一个基本场景。该场景将模仿我们这个时代最流行的 2D 游戏之一，*愤怒的小鸟*TM。

## 准备工作

对于这个教程，您需要一台 Windows 机器和安装了 Visual Studio 的版本。不需要其他先决条件。

## 操作步骤…

在这个教程中，我们将发现使用 Box2D 为 2D 游戏添加一个简单的架构是多么容易：

```cpp
class Tiles : public Test
{
public:
  enum
  {
    e_count = 10
  };

  Tiles()
  {
    m_fixtureCount = 0;
    b2Timer timer;

    {
      float32 a = 1.0f;
      b2BodyDef bd;
      bd.position.y = -a;
      b2Body* ground = m_world->CreateBody(&bd);

#if 1
      int32 N = 200;
      int32 M = 10;
      b2Vec2 position;
      position.y = 0.0f;
      for (int32 j = 0; j < M; ++j)
      {
        position.x = -N * a;
        for (int32 i = 0; i < N; ++i)
        {
          b2PolygonShape shape;
          shape.SetAsBox(a, a, position, 0.0f);
          ground->CreateFixture(&shape, 0.0f);
          ++m_fixtureCount;
          position.x += 2.0f * a;
        }
        position.y -= 2.0f * a;
      }
#else
      int32 N = 200;
      int32 M = 10;
      b2Vec2 position;
      position.x = -N * a;
      for (int32 i = 0; i < N; ++i)
      {
        position.y = 0.0f;
        for (int32 j = 0; j < M; ++j)
        {
          b2PolygonShape shape;
          shape.SetAsBox(a, a, position, 0.0f);
          ground->CreateFixture(&shape, 0.0f);
          position.y -= 2.0f * a;
        }
        position.x += 2.0f * a;
      }
#endif
    }

    {
      float32 a = 1.0f;
      b2PolygonShape shape;
      shape.SetAsBox(a, a);

      b2Vec2 x(-7.0f, 0.75f);
      b2Vec2 y;
      b2Vec2 deltaX(1.125f, 2.5f);
      b2Vec2 deltaY(2.25f, 0.0f);

      for (int32 i = 0; i < e_count; ++i)
      {
        y = x;

        for (int32 j = i; j < e_count; ++j)
        {
          b2BodyDef bd;
          bd.type = b2_dynamicBody;
          bd.position = y;

          b2Body* body = m_world->CreateBody(&bd);
          body->CreateFixture(&shape, 5.0f);
          ++m_fixtureCount;
          y += deltaY;
        }

        x += deltaX;
      }
    }

    m_createTime = timer.GetMilliseconds();
  }

  void Step(Settings* settings)
  {
    const b2ContactManager& cm = m_world->GetContactManager();
    int32 height = cm.m_broadPhase.GetTreeHeight();
    int32 leafCount = cm.m_broadPhase.GetProxyCount();
    int32 minimumNodeCount = 2 * leafCount - 1;
    float32 minimumHeight = ceilf(logf(float32(minimumNodeCount)) / logf(2.0f));
    g_debugDraw.DrawString(5, m_textLine, "dynamic tree height = %d, min = %d", height, int32(minimumHeight));
    m_textLine += DRAW_STRING_NEW_LINE;

    Test::Step(settings);

    g_debugDraw.DrawString(5, m_textLine, "create time = %6.2f ms, fixture count = %d",
      m_createTime, m_fixtureCount);
    m_textLine += DRAW_STRING_NEW_LINE;

  }

  static Test* Create()
  {
    return new Tiles;
  }

  int32 m_fixtureCount;
  float32 m_createTime;
};

#endif
```

## 工作原理…

在这个示例中，我们使用 Box2D 引擎来计算物理。如前所述，`Test Entries`的主类用于存储应用程序的名称和静态创建方法。在这种情况下，应用程序的名称是`Tiles`。在瓷砖应用程序中，我们使用 Box2D 形状和函数创建了一个物理世界。瓷砖金字塔是用方块创建的。这些方块是动态的，这意味着它们会根据施加在它们身上的力而做出反应和移动。基座或地面也由瓷砖制成。但是，这些瓷砖是静止的，不会移动。我们为构成地面和金字塔的所有瓷砖分配位置和速度。逐个为每个瓷砖分配位置和速度是不切实际的，因此我们使用迭代循环来实现这一点。

场景构建完成后，我们可以通过鼠标点击与金字塔进行交互。从 GUI 中，还可以打开或关闭其他属性。按下空格键还会在随机位置触发一个球，它将摧毁瓷砖的形成，就像*愤怒的小鸟*一样。我们还可以编写逻辑，使所有与地面碰撞的瓷砖消失，并在每次发生碰撞时为得分加分，然后我们就有了一个小型的 2D *愤怒的小鸟*克隆。

# 制作 3D 游戏

当我们把注意力从 2D 物理转移到 3D 物理时，变化不大。现在我们需要担心另一个维度。如前面的教程中所述，我们仍然需要维护环境，使其遵循牛顿规则并解决约束。在 3D 空间中旋转物体时可能会出现很多问题。在这个教程中，我们将使用 Bullet Engine SDK 来查看 3D 物理的一个非常基本的实现。

## 准备工作

对于这个教程，您需要一台 Windows 机器和安装了 Visual Studio 的版本。

## 操作步骤…

在这个示例中，我们将看到在 3D 中编写物理世界是多么容易。

对于广相碰撞，请查看以下代码片段：

```cpp
void  b3DynamicBvhBroadphase::getAabb(int objectId,b3Vector3& aabbMin, b3Vector3& aabbMax ) const
{
  const b3DbvtProxy*            proxy=&m_proxies[objectId];
  aabbMin = proxy->m_aabbMin;
  aabbMax = proxy->m_aabbMax;
}
```

对于窄相碰撞，请参阅以下代码：

```cpp
void b3CpuNarrowPhase::computeContacts(b3AlignedObjectArray<b3Int4>& pairs, b3AlignedObjectArray<b3Aabb>& aabbsWorldSpace, b3AlignedObjectArray<b3RigidBodyData>& bodies)
{
  int nPairs = pairs.size();
  int numContacts = 0;
  int maxContactCapacity = m_data->m_config.m_maxContactCapacity;
  m_data->m_contacts.resize(maxContactCapacity);

  for (int i=0;i<nPairs;i++)
  {
    int bodyIndexA = pairs[i].x;
    int bodyIndexB = pairs[i].y;
    int collidableIndexA = bodies[bodyIndexA].m_collidableIdx;
    int collidableIndexB = bodies[bodyIndexB].m_collidableIdx;

    if (m_data->m_collidablesCPU[collidableIndexA].m_shapeType == SHAPE_SPHERE &&
      m_data->m_collidablesCPU[collidableIndexB].m_shapeType == SHAPE_CONVEX_HULL)
    {
//     computeContactSphereConvex(i,bodyIndexA,bodyIndexB,collidableIndexA,collidableIndexB,&bodies[0],
//     &m_data->m_collidablesCPU[0],&hostConvexData[0],&hostVertices[0],&hostIndices[0],&hostFaces[0],&hostContacts[0],nContacts,maxContactCapacity);
    }

    if (m_data->m_collidablesCPU[collidableIndexA].m_shapeType == SHAPE_

  m_data->m_contacts.resize(numContacts);

<. . . . . . .  More code to follow . . . . . . . .>
}
```

## 工作原理…

正如我们从上面的示例中看到的，即使在 3D 中，物理碰撞系统也必须分为阶段：广相和窄相。在广相碰撞中，我们现在考虑 Vector3，而不仅仅是两个浮点数，因为现在我们有三个轴（*x*，*y*和*z*）。我们需要输入对象 ID，然后检查边界框的范围。同样，对于窄相碰撞，我们的问题域和计算保持不变。我们现在将其更改为支持 3D。先前的示例显示了在窄相碰撞中需要找到接触点的问题的一部分。我们创建一个数组，并根据碰撞回调保存所有接触点。稍后，我们可以编写其他方法来检查这些点是否重叠。

# 创建一个粒子系统

粒子系统在游戏中非常重要，可以增加游戏整体感觉的视觉表现。粒子系统很容易编写，只是一个或多个粒子的集合。因此，我们需要创建一个具有一些属性的单个粒子，然后让粒子系统决定需要多少粒子。

## 准备工作

对于这个示例，您需要一台 Windows 机器和安装了 Visual Studio 的版本。

## 如何做…

添加一个名为`Source.cpp`的源文件。然后将以下代码添加到其中：

```cpp
class Particle

{
  Vector3 location;
  Vector3 velocity;
  Vector3 acceleration;
  float lifespan;

  Particle(Vector3 vec)
  {

    acceleration = new Vector3(.05, 0.05);
    velocity = new Vector3(random(-3, 3), random(-4, 0));
    location = vec.get();
    lifespan = 125.0;
  }

    void run()
    {
    update();
    display();
    }

  void update() {
    velocity.add(acceleration);
    location.add(velocity);
    lifespan -= 2.0;
  }

  void display()
  {
    stroke(0, lifespan);
    fill(0, lifespan);
    trapezoid(location.x, location.y, 8, 8);
  }

    boolean isDead()
    {
    if (lifespan < 0.0) {
      return true;
    }
    else {
      return false;
    }
  }
};

Particle p;

void setup()
{
  size(800, 600);
  p = new Particle(new Vector3(width / 2, 10));
}

void draw()
{
  for (int i = 0; i < particles.size(); i++) {
    Particle p = particles.get(i);
    p.run();

      if (p.isDead()) {
        particles.remove(i);
      }
  }
}
```

## 工作原理…

正如我们在示例中看到的，我们的第一个任务是创建一个`particle`类。`particle`类将具有诸如`velocity`、`acceleration`、`position`和`lifespan`之类的属性。因为我们在 3D 空间中制作粒子，所以我们使用 Vector3 来表示粒子的属性。如果我们要在 2D 空间中创建粒子，我们将使用 Vector2 来做到这一点。在构造函数中，我们分配属性的起始值。然后我们有两个主要函数，`update`和`display`。`update`函数在每一帧更新`velocity`和`position`，并减少寿命，以便在寿命结束时消失。在`display`函数中，我们需要指定我们希望如何查看粒子：它是否应该有描边或填充等。在这里，我们还必须指定粒子的形状。最常见的形状是球体或圆锥体。我们使用了梯形只是为了表示我们可以指定任何形状。最后，从客户程序中，我们需要调用这个对象，然后访问各种函数来显示粒子。

然而，所有这些只会在屏幕上显示一个粒子。当然，我们可以创建一个包含 100 个对象的数组，这样就可以在屏幕上显示 100 个粒子。更好的方法是创建一个粒子系统，它可以创建一个粒子数组。要绘制的粒子数量由客户程序指定。根据请求，粒子系统绘制所需数量的粒子。此外，必须有一个函数来确定哪些粒子需要从屏幕上移除。这取决于每个粒子的寿命。

# 在游戏中使用布娃娃

**布娃娃物理**是一种特殊的程序动画，通常用作游戏中传统静态死亡动画的替代品。布娃娃动画的整个理念是，角色死亡后，身体的骨骼就像布娃娃一样行为。因此得名。这与现实主义无关，但为游戏增添了特别的乐趣元素。

## 准备工作

对于这个示例，您需要一台 Windows 机器和安装了 Visual Studio 的版本。还需要 DirectX SDK；最好使用 DirectX 2010 年 6 月版。

## 如何做…

让我们看一下以下代码：

```cpp
#include "RagDoll.h"
#include "C3DETransform.h"
#include "PhysicsFactory.h"
#include "Physics.h"
#include "DebugMemory.h"

RagDoll::RagDoll(C3DESkinnedMesh * a_skinnedMesh, C3DESkinnedMeshContainer * a_skinnedMeshContainer, int totalParts, int totalConstraints)
{
  m_skinnedMesh = a_skinnedMesh;
  m_skinnedMeshContainer = a_skinnedMeshContainer;
  m_totalParts = totalParts;
  m_totalConstraints = totalConstraints;

  m_ragdollBodies = (btRigidBody**)malloc(sizeof(btRigidBody) * totalParts);
  m_ragdollShapes = (btCollisionShape**)malloc(sizeof(btCollisionShape) * totalParts);
  m_ragdollConstraints = (btTypedConstraint**)malloc(sizeof(btTypedConstraint) * totalConstraints);

  m_boneIndicesToFollow = (int*) malloc(sizeof(int) * m_skinnedMesh->GetTotalBones());

  m_totalBones = m_skinnedMesh->GetTotalBones();

  m_bonesCurrentWorldPosition = (D3DXMATRIX**)malloc(sizeof(D3DXMATRIX) * m_totalBones);

  m_boneToPartTransforms = (D3DXMATRIX**)malloc(sizeof(D3DXMATRIX) * m_totalBones);

  for(int i = 0; i < totalConstraints; i++)
  {
    m_ragdollConstraints[i] = NULL;
  }

  for(int i = 0; i < totalParts; i++)
  {
    m_ragdollBodies[i] = NULL;
    m_ragdollShapes[i] = NULL;

  }

  for(int i = 0; i < m_totalBones; i++)
  {    
    m_boneToPartTransforms[i] = NULL;
    m_boneToPartTransforms[i] = new D3DXMATRIX();

    m_bonesCurrentWorldPosition[i] = NULL;
    m_bonesCurrentWorldPosition[i] = new D3DXMATRIX();
  }

  m_constraintCount = 0;
}

RagDoll::~RagDoll()
{
  free(m_ragdollConstraints);  
  free(m_ragdollBodies);
  free(m_ragdollShapes);  

  for(int i = 0; i < m_totalBones; i++)
  {

    delete m_boneToPartTransforms[i];
    m_boneToPartTransforms[i] = NULL;

    delete m_bonesCurrentWorldPosition[i];
    m_bonesCurrentWorldPosition[i] = NULL;
  }

  free(m_bonesCurrentWorldPosition);
  free(m_boneToPartTransforms);    
  free(m_boneIndicesToFollow);    

}

int RagDoll::GetTotalParts()
{
  return m_totalParts;
}

int RagDoll::GetTotalConstraints()
{
  return m_totalConstraints;
}

C3DESkinnedMesh *RagDoll::GetSkinnedMesh()
{
  return m_skinnedMesh;
}

//sets up a part of the ragdoll
//int index = the index number of the part
//int setMeshBoneTransformIndex = the bone index that this part is linked to,
//float offsetX, float offsetY, float offsetZ = translatin offset for the part in bone local space
//float mass = part's mass,
//btCollisionShape * a_shape = part's collision shape
void RagDoll::SetPart(int index, int setMeshBoneTransformIndex, float offsetX, float offsetY, float offsetZ,float mass, btCollisionShape * a_shape)
{  
  m_boneIndicesToFollow[setMeshBoneTransformIndex] = index;

  //we set the parts position according to the skinned mesh current position

  D3DXMATRIX t_poseMatrix = m_skinnedMeshContainer->GetPoseMatrix()[setMeshBoneTransformIndex];
  D3DXMATRIX *t_boneWorldRestMatrix = m_skinnedMesh->GetBoneWorldRestMatrix(setMeshBoneTransformIndex);

  D3DXMATRIX t_boneWorldPosition;
  D3DXMatrixMultiply(&t_boneWorldPosition, t_boneWorldRestMatrix, &t_poseMatrix);

  D3DXVECTOR3 * t_head = m_skinnedMesh->GetBoneHead(setMeshBoneTransformIndex);
  D3DXVECTOR3 * t_tail = m_skinnedMesh->GetBoneTail(setMeshBoneTransformIndex);        

  float tx = t_tail->x - t_head->x;
  float ty = t_tail->y - t_head->y;
  float tz = t_tail->z - t_head->z;

  //part's world matrix
  D3DXMATRIX *t_partMatrix = new D3DXMATRIX();
  *t_partMatrix = t_boneWorldPosition;

  D3DXMATRIX *t_centerOffset = new D3DXMATRIX();
  D3DXMatrixIdentity(t_centerOffset);
  D3DXMatrixTranslation(t_centerOffset, (tx / 2.0f) + offsetX, (ty / 2.0f) + offsetY, (tz/2.0f) + offsetZ);
  D3DXMatrixMultiply(t_partMatrix, t_partMatrix, t_centerOffset);

  D3DXVECTOR3 t_pos;
  D3DXVECTOR3 t_scale;
  D3DXQUATERNION t_rot;

  D3DXMatrixDecompose(&t_scale, &t_rot, &t_pos, t_partMatrix);

  btRigidBody* body = PhysicsFactory::GetInstance()->CreateRigidBody(mass,t_pos.x, t_pos.y, t_pos.z, t_rot.x, t_rot.y, t_rot.z, t_rot.w, a_shape);

  D3DXMATRIX t_partInverse;
  D3DXMatrixInverse(&t_partInverse, NULL, t_partMatrix);

  //puts the bone's matrix in part's local space, and store it in m_boneToPartTransforms
  D3DXMatrixMultiply(m_boneToPartTransforms[setMeshBoneTransformIndex], &t_boneWorldPosition, &t_partInverse);

  m_ragdollBodies[index] = body;

  delete t_partMatrix;
  t_partMatrix = NULL;

  delete t_centerOffset;
  t_centerOffset = NULL;

}

//when a bone is not going to have a part directly linked to it, it needs to follow a bone that has
//a part linked to
//int realBoneIndex = the bone that has no part linked
//int followBoneIndex = the bone that has a part linked
void RagDoll::SetBoneRelation(int realBoneIndex, int followBoneIndex)
{
  //it is going to the same thing the setPart method does, but the bone it is going to take
  //as a reference is the one passed as followBoneIndex and the the part's matrix is below
  //by calling GetPartForBoneIndex. Still there is going to be a new entry in m_boneToPartTransforms
  //which is the bone transform in the part's local space
  int partToFollowIndex = GetPartForBoneIndex(followBoneIndex);

  m_boneIndicesToFollow[realBoneIndex] = partToFollowIndex;

  D3DXMATRIX t_poseMatrix = m_skinnedMeshContainer->GetPoseMatrix()[realBoneIndex];
  D3DXMATRIX *t_boneWorldRestMatrix = m_skinnedMesh->GetBoneWorldRestMatrix(realBoneIndex);

  D3DXMATRIX t_boneWorldPosition;
  D3DXMatrixMultiply(&t_boneWorldPosition, t_boneWorldRestMatrix, &t_poseMatrix);

  D3DXMATRIX *t_partMatrix = new D3DXMATRIX();
  btTransform t_partTransform = m_ragdollBodies[partToFollowIndex]->getWorldTransform();
  *t_partMatrix = BT2DX_MATRIX(t_partTransform);

  D3DXMATRIX t_partInverse;
  D3DXMatrixInverse(&t_partInverse, NULL, t_partMatrix);

  D3DXMatrixMultiply(m_boneToPartTransforms[realBoneIndex], &t_boneWorldPosition, &t_partInverse);    

  delete t_partMatrix;
  t_partMatrix = NULL;  

}

btRigidBody ** RagDoll::GetRadollParts()
{
  return m_ragdollBodies;
}

btTypedConstraint **RagDoll::GetConstraints()
{
  return m_ragdollConstraints;
}

void RagDoll::AddConstraint(btTypedConstraint *a_constraint)
{
  m_ragdollConstraints[m_constraintCount] = a_constraint;
  m_constraintCount++;
}

//This method will return the world position that the given bone should have
D3DXMATRIX * RagDoll::GetBoneWorldTransform(int boneIndex)
{
  //the part world matrix is fetched, and then we apply the bone transform offset to obtain
  //the bone's world position
  int t_partIndex = GetPartForBoneIndex(boneIndex);

  btTransform  t_transform = m_ragdollBodies[t_partIndex]->getWorldTransform();    
  D3DXMATRIX t_partMatrix = BT2DX_MATRIX(t_transform);

  D3DXMatrixIdentity(m_bonesCurrentWorldPosition[boneIndex]);
  D3DXMatrixMultiply(m_bonesCurrentWorldPosition[boneIndex], m_boneToPartTransforms[boneIndex], &t_partMatrix);

  return m_bonesCurrentWorldPosition[boneIndex];
}

int RagDoll::GetPartForBoneIndex(int boneIndex)
{
  for(int i = 0; i < m_totalBones;i ++)
  {
    if(i == boneIndex)
    {
      return m_boneIndicesToFollow[i];
    }
  }

  return -1;
}
```

## 工作原理…

从上面的例子中可以看出，对于这个例子，你需要一个蒙皮网格模型。网格模型可以从一些免版税的网站下载，也可以通过 Blender 或任何其他 3D 软件包（如 Maya 或 Max）制作。由于布娃娃的整个概念是基于网格的骨骼，我们必须确保 3D 模型的骨骼设置正确。

之后，代码中有很多小部分。问题的第一部分是编写一个骨骼容器类，用于存储所有骨骼信息。接下来，我们需要使用骨骼容器类，并使用 Bullet 物理 SDK，为每个骨骼分配一个刚体。在设置好刚体之后，我们需要再次遍历骨骼，并创建骨骼之间的关系，这样当一个骨骼移动时，相邻的骨骼也会移动。最后，我们还需要添加约束，以便当物理引擎模拟布娃娃时，可以正确解决约束并将结果输出到骨骼。


# 第十章：游戏开发中的多线程

在本章中，将涵盖以下配方：

+   游戏中的并发性-创建线程

+   加入和分离线程

+   向线程传递参数

+   避免死锁

+   数据竞争和互斥

+   编写线程安全的类

# 介绍

要理解多线程，让我们首先了解线程的含义。线程是并发执行的单位。它有自己的调用堆栈，用于调用的方法，它们的参数和局部变量。每个应用程序在启动时至少有一个正在运行的线程，即主线程。当我们谈论多线程时，意味着一个进程有许多独立和并发运行的线程，但具有共享内存。通常，多线程与多处理混淆。多处理器有多个运行的进程，每个进程都有自己的线程。

尽管多线程应用程序可能编写起来复杂，但它们是轻量级的。然而，多线程架构不适合分布式应用程序。在游戏中，我们可能有一个或多个线程在运行。关键问题是何时以及为什么应该使用多线程。虽然这是相当主观的，但如果您希望多个任务同时发生，您将使用多线程。因此，如果您不希望游戏中的物理代码或音频代码等待主循环完成处理，您将对物理和音频循环进行多线程处理。

# 游戏中的并发性-创建线程

编写多线程代码的第一步是生成一个线程。在这一点上，我们必须注意应用程序已经运行了一个活动线程，即主线程。因此，当我们生成一个线程时，应用程序中将有两个活动线程。

## 准备工作

要完成这个配方，您需要一台运行 Windows 和 Visual Studio 的计算机。不需要其他先决条件。

## 如何做...

在这个配方中，我们将看到生成线程有多么容易。添加一个名为`Source.cpp`的源文件，并将以下代码添加到其中：

```cpp
int ThreadOne()
{
  std::cout << "I am thread 1" << std::endl;
  return 0;
}

int main()
{
  std::thread T1(ThreadOne);

  if (T1.joinable()) // Check if can be joined to the main thread
    T1.join();     // Main thread waits for this to finish

  _getch();
  return 0;
}
```

## 它是如何工作的...

第一步是包含头文件`thread.h`。这使我们可以访问所有内置库，以便创建我们的多线程应用程序所需的所有库。下一步是创建我们需要线程的任务或函数。在这个例子中，我们创建了一个名为`ThreadOne`的函数。这个函数代表我们可以用来多线程的任何函数。这可以是物理函数，音频函数，或者我们可能需要的任何函数。为简单起见，我们使用了一个打印消息的函数。下一步是生成一个线程。我们只需要编写关键字`thread`，为线程分配一个名称（`T1`），然后编写我们想要线程的函数/任务。在这种情况下，它是`ThreadOne`。

这会生成一个线程，并且不会独立于主线程执行。

# 加入和分离线程

线程生成后，它作为一个新任务开始执行，与主线程分开。然而，可能存在一些情况，我们希望任务重新加入主线程。这是可能的。我们可能还希望线程始终与主线程保持分离。这也是可能的。然而，在连接到主线程和分离时，我们必须采取一些预防措施。

## 准备工作

您需要一台运行 Windows 和 Visual Studio 的工作计算机。

## 如何做...

在这个配方中，我们将看到加入和分离线程有多么容易。添加一个名为`Source.cpp`的源文件。将以下代码添加到其中：

```cpp
int ThreadOne()
{
  std::cout << "I am thread 1" << std::endl;
  return 0;
}

int ThreadTwo()
{
  std::cout << "I am thread 2" << std::endl;
  return 0;
}

int main()
{
  std::thread T1(ThreadOne);
  std::thread T2(ThreadTwo);

  if (T1.joinable()) // Check if can be joined to the main thread
    T1.join();     // Main thread waits for this to finish

  T2.detach();    //Detached from main thread

  _getch();
  return 0;
}
```

## 它是如何工作的...

在上面的例子中，首先生成了两个线程。这两个线程是`T1`和`T2`。当线程被生成时，它们会独立并发地运行。然而，当需要将任何线程重新加入到主线程时，我们也可以这样做。首先，我们需要检查线程是否可以加入到主线程。我们可以通过 joinable 函数来实现这一点。如果函数返回`true`，则线程可以加入到主线程。我们可以使用`join`函数加入到主线程。如果我们直接加入，而没有首先检查线程是否可以加入到主线程，可能会导致主线程无法接受该线程而出现问题。线程加入到主线程后，主线程会等待该线程完成。

如果我们想要将线程从主线程分离，我们可以使用`detach`函数。然而，在我们将其从主线程分离后，它将永远分离。

# 向线程传递参数

就像在函数中一样，我们可能还想将参数和参数传递给线程。由于线程只是任务，而任务只是一系列函数的集合，因此有必要了解如何向线程发送参数。如果我们可以在运行时向线程发送参数，那么线程可以动态执行所有操作。在大多数情况下，我们会将物理、人工智能或音频部分线程化。所有这些部分都需要接受参数的函数。

## 准备工作

你需要一台 Windows 机器和一个安装好的 Visual Studio 副本。不需要其他先决条件。

## 如何做…

在这个食谱中，我们将发现为我们的游戏添加启发式函数进行路径规划有多么容易。添加一个名为`Source.cpp`的源文件。将以下代码添加到其中：

```cpp
class Wrapper
{
public:
  void operator()(std::string& msg)
  {
    msg = " I am from T1";
    std::cout << "T1 thread initiated" << msg << std::endl;

  }
};

int main()
{
  std::string s = "This is a message";
  std::cout << std::this_thread::get_id() << std::endl;

  std::thread T1((Wrapper()), std::move(s));
  std::cout << T1.get_id() << std::endl;

  std::thread T2 = std::move(T1);
  T2.join();

  _getch();

}
```

## 工作原理…

传递参数的最佳方法是编写一个`Wrapper`类并重载`()`运算符。在我们重载`()`运算符之后，我们可以向线程发送参数。为此，我们创建一个字符串并将字符串存储在一个变量中。然后我们需要像往常一样生成一个线程；然而，我们不仅仅传递函数名，而是传递类名和字符串。在线程中，我们需要通过引用传递参数，因此我们可以使用`ref`函数。然而，更好的方法是使用`move`函数，其中我们注意内存位置本身并将其传递给参数。`operator`函数接受字符串并打印消息。

如果我们想创建一个新线程并使其与第一个线程相同，我们可以再次使用`move`函数来实现这一点。除此之外，我们还可以使用`get_id`函数来获取线程的 ID。

# 避免死锁

当两个或更多任务想要使用相同的资源时，就会出现竞争条件。在一个任务完成使用资源之前，另一个任务无法访问它。这被称为**死锁**，我们必须尽一切努力避免死锁。例如，资源`Collision`和资源`Audio`被进程`Locomotion`和进程`Bullet`使用：

+   `Locomotion`开始使用`Collision`

+   `Locomotion`和`Bullet`尝试开始使用`Audio`

+   `Bullet`“赢得”并首先获得`Audio`

+   现在`Bullet`需要使用`Collision`

+   `Collision`被`Locomotion`锁定，它正在等待`Bullet`

## 准备工作

对于这个食谱，你需要一台 Windows 机器和一个安装好的 Visual Studio 副本。

## 如何做…

在这个食谱中，我们将发现避免死锁有多么容易：

```cpp
#include <thread>
#include <string>
#include <iostream>

using namespace std;

void Physics()
{
  for (int i = 0; i > -100; i--)
    cout << "From Thread 1: " << i << endl;

}

int main()
{
  std::thread t1(Physics);
  for (int i = 0; i < 100; i++)
    cout << "From main: " << i << endl;

  t1.join();

  int a;
  cin >> a;
  return 0;
}
```

## 工作原理…

在上面的例子中，我们生成了一个名为`t1`的线程，它开始一个函数以从 0 到-100 打印数字，递减 1。还有一个主线程，它开始从 0 到 100 打印数字，递增 1。同样，我们选择了这些函数是为了简单理解。这些可以很容易地被*A*算法和搜索算法或其他任何我们想要的东西所替代。

如果我们看控制台输出，我们会注意到它非常混乱。原因是`cout`对象被主线程和`t1`同时使用。因此，发生了数据竞争的情况。每次谁赢得了竞争，谁就会显示数字。我们必须尽一切努力避免这种编程结构。很多时候，它会导致死锁和中断。

# 数据竞争和互斥锁

数据竞争条件在多线程应用程序中非常常见，但我们必须避免这种情况，以防止死锁发生。**互斥锁**帮助我们克服死锁。互斥锁是一个程序对象，允许多个程序线程共享相同的资源，比如文件访问，但不是同时。当程序启动时，会创建一个带有唯一名称的互斥锁。

## 准备工作

对于这个食谱，你需要一台 Windows 机器和安装了 Visual Studio 的版本。

## 如何做…

在这个食谱中，我们将看到理解数据竞争和互斥锁是多么容易。添加一个名为`Source.cpp`的源文件，并将以下代码添加到其中：

```cpp
#include <thread>
#include <string>
#include <mutex>
#include <iostream>

using namespace std;

std::mutex MU;

void Locomotion(string msg, int id)
{
  std::lock_guard<std::mutex> guard(MU); //RAII
  //MU.lock();
  cout << msg << id << endl;
  //MU.unlock();
}
void InterfaceFunction()
{
  for (int i = 0; i > -100; i--)
    Locomotion(string("From Thread 1: "), i);

}

int main()
{
  std::thread FirstThread(InterfaceFunction);
  for (int i = 0; i < 100; i++)
    Locomotion(string("From Main: "), i);

  FirstThread.join();

  int a;
  cin >> a;
  return 0;
}
```

## 它是如何工作的…

在这个例子中，主线程和`t1`都想显示一些数字。然而，由于它们都想使用`cout`对象，这就产生了数据竞争的情况。为了避免这种情况，一种方法是使用互斥锁。因此，在执行`print`语句之前，我们有`mutex.lock`，在`print`语句之后，我们有`mutex.unlock`。这样可以工作，并防止数据竞争条件，因为互斥锁将允许一个线程使用资源，并使另一个线程等待它。然而，这个程序还不是线程安全的。这是因为如果`cout`语句抛出错误或异常，互斥锁将永远不会被解锁，其他线程将始终处于`等待`状态。

为了避免这种情况，我们将使用 C++的**资源获取即初始化技术**（**RAII**）。我们在函数中添加一个内置的锁保护。这段代码是异常安全的，因为 C++保证所有堆栈对象在封闭范围结束时被销毁，即所谓的**堆栈展开**。当从函数返回时，锁和文件对象的析构函数都将被调用，无论是否抛出了异常。因此，如果发生异常，它不会阻止其他线程永远等待。尽管这样做，这个应用程序仍然不是线程安全的。这是因为`cout`对象是一个全局对象，因此程序的其他部分也可以访问它。因此，我们需要进一步封装它。我们稍后会看到这一点。

# 编写一个线程安全的类

在处理多个线程时，编写一个线程安全的类变得非常重要。如果我们不编写线程安全的类，可能会出现许多复杂情况，比如死锁。我们还必须记住，当我们编写线程安全的类时，就不会有数据竞争和互斥锁的潜在危险。

## 准备工作

对于这个食谱，你需要一台 Windows 机器和安装了 Visual Studio 的版本。

## 如何做…

在这个食谱中，我们将看到在 C++中编写一个线程安全的类是多么容易。添加一个名为`Source.cpp`的源文件，并将以下代码添加到其中：

```cpp
#include <thread>
#include <string>
#include <mutex>
#include <iostream>
#include <fstream>

using namespace std;

class DebugLogger
{
  std::mutex MU;
  ofstream f;
public:
  DebugLogger()
  {
    f.open("log.txt");
  }
  void ResourceSharingFunction(string id, int value)
  {
    std::lock_guard<std::mutex> guard(MU); //RAII
    f << "From" << id << ":" << value << endl;
  }

};

void InterfaceFunction(DebugLogger& log)
{
  for (int i = 0; i > -100; i--)
    log.ResourceSharingFunction(string("Thread 1: "), i);

}

int main()
{
  DebugLogger log;
  std::thread FirstThread(InterfaceFunction,std::ref(log));
  for (int i = 0; i < 100; i++)
    log.ResourceSharingFunction(string("Main: "), i);

  FirstThread.join();

  int a;
  cin >> a;
  return 0;
}
```

## 它是如何工作的…

在上一个食谱中，我们看到尽管编写了互斥锁和锁，我们的代码仍然不是线程安全的。这是因为我们使用了一个全局对象`cout`，它也可以从代码的其他部分访问，因此不是线程安全的。因此，我们通过添加一层抽象来避免这样做，并将结果输出到日志文件中。

我们已经创建了一个名为`Logfile`的类。在这个类里，我们创建了一个锁保护和一个互斥锁。除此之外，我们还创建了一个名为`f`的流对象。使用这个对象，我们将内容输出到一个文本文件中。需要访问这个功能的线程将需要创建一个`LogFile`对象，然后适当地使用这个函数。我们在 RAII 系统中使用了锁保护。由于这种抽象层，外部无法使用这个功能，因此是非常安全的。

然而，即使在这个程序中，我们也需要采取一定的预防措施。我们应该采取的第一项预防措施是不要从任何函数中返回`f`。此外，我们必须小心，`f`不应该直接从任何其他类或外部函数中获取。如果我们做了上述任何一项，资源`f`将再次可用于程序的外部部分，将不受保护，因此将不再是线程安全的。


# 第十一章：游戏开发中的网络

本章将涵盖以下配方：

+   理解不同的层

+   选择适当的协议

+   序列化数据包

+   在游戏中使用套接字编程

+   发送数据

+   接收数据

+   处理延迟

+   使用同步模拟

+   使用感兴趣区域过滤

+   使用本地感知过滤

# 介绍

在现代视频游戏时代，网络在游戏的整体可玩性中扮演着重要角色。单人游戏提供平均约 15-20 小时的游戏时间。然而，通过多人游戏（联网）功能，游戏时间呈指数增长，因为现在用户必须与其他人类对手进行游戏并改进他们的战术。无论是 PC 游戏、游戏机还是移动游戏，具有多人游戏功能如今已成为一种常见特性。对于游戏的免费模式，其中货币化和收入模式基于应用内购买和广告，游戏必须每天拥有数千或数百万活跃用户。这是游戏赚钱的唯一途径。当我们谈论多人游戏时，我们不应该自欺欺人地认为这仅限于实时**PvP**（玩家对玩家）。它也可以是异步多人游戏，玩家与活跃玩家的数据竞争，而不是与玩家本身竞争。它给人一种错觉，即玩家正在与真实玩家竞争。此外，随着社交媒体的出现，网络也在帮助你与朋友竞争。例如，在*Candy Crush*中，完成一个关卡后，你会看到你的朋友在同一关卡中的表现以及下一个要击败的朋友是谁。所有这些增加了游戏的热度，并迫使你继续玩下去。

# 理解不同的层

从技术角度看，整个网络模型被划分为多个层。这个模型也被称为**OSI**（**开放系统互连**）模型。每一层都有特殊的意义，必须正确理解才能与拓扑的其他层进行交互。

## 准备就绪

要完成这个配方，您需要一台运行 Windows 的机器。

## 如何做…

在这个配方中，我们将看到理解网络拓扑的不同层有多容易。看看下面的图表：

![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/4929_11_01.jpg)

## 工作原理…

要理解 OSI 模型，我们必须从堆栈的底部向上查看模型。OSI 模型的层包括：

+   **物理层**：这建立了与网络的实际物理连接。这取决于我们是使用铜线还是光纤。它定义了所使用的网络拓扑结构，环形或总线等。它还定义了传输模式：是单工、半双工还是全双工。

+   **数据链路层**：这提供了两个连接节点之间的实际链接。数据链路层有两个子层：**MAC**层（**媒体访问控制**）和**LLC**层（**逻辑链路控制**）。

+   **网络层**：这一层提供了传输可变长度数据（称为**数据报**）的功能手段。传输发生在同一网络上的一个连接节点到另一个连接节点。这形成了 IP。

+   **传输层**：这一层还提供了传输数据的功能手段。数据从源传输到目的地，经过一个或多个网络。这里使用的一些协议是 TCP 和 UDP。**TCP**是**传输控制协议**，是一个安全连接。**UDP**是**用户数据报协议**，是不太安全的。在视频游戏中，我们同时使用 TCP 和 UDP 协议。当用户需要登录服务器时，我们使用 TCP，因为它更安全，因为除非服务器对先前的数据做出确认，否则不会发送来自客户端的下一个信息。然而，它可能会比较慢，所以如果安全性比速度更重要，我们使用 TCP。用户登录后，游戏在其他玩家加入后开始。现在我们在大多数情况下使用 UDP，因为速度比安全性更重要，而少量丢失的数据包可能会产生巨大影响。UDP 数据包并不总是被接收，因为没有确认。

+   **会话层**：这一层控制网络和远程计算机之间的连接。这一层负责建立、管理和终止连接。

+   **表示层**：这一层控制需要在连接之间建立的不同语义。所有加密逻辑都写在这一层。

+   **应用层**：这一层处理与软件应用程序本身的通信。这是离最终用户最近的一层。

# 选择适当的协议

在游戏中，大部分时间都需要做一个重要的决定：使用 TCP 还是 UDP。决定往往会偏向 UDP，但了解两者之间的区别仍然很重要。

## 准备工作

你需要一台 Windows 机器。不需要其他先决条件。

## 如何做…

在这个示例中，我们将发现决定使用 TCP 还是 UDP 有多么容易。

问以下问题：

+   系统是否需要可靠交付？

+   是否需要重传的要求？

+   系统是否需要任何握手机制？

+   它需要什么样的拥塞控制？

+   速度是否是系统考虑的因素？

## 它是如何工作的…

TCP 和 UDP 建立在 IP 层之上：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/4929_11_02.jpg)

TCP 连接被认为是可靠的，因为启用了双向握手系统。一旦消息传递到终点，就会发送一个确认消息。它还支持各种其他服务，如拥塞控制和多路复用。TCP 也是全双工的，使其成为一个相当强大的连接。它通过字节序列号来处理数据的可靠传输。它设置了一个超时函数，并根据超时来决定包是否已经被传递。下图显示了握手协议是如何建立的：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/4929_11_03.jpg)

TCP 的另一个机制是滑动窗口机制，它保证了数据的可靠传递。它确保数据包按顺序传递，并在发送方和接收方之间建立了流量控制。

当我们不太关心数据包的顺序交付时，就会使用 UDP。主要关注的是数据包的快速交付。没有可靠性，也没有保证数据包会被交付。

需要有序交付的应用程序必须自行恢复数据报的顺序。数据报可以被写入目标地址，而不知道它是否存在或正在监听。消息也可以广播到特定子网上的所有主机。*DOOM*就是这样做的。有时，如果我们需要最小的可靠性，UDP 可以添加该功能。在那时，它也被称为可靠 UDP。

# 序列化数据包

序列化是网络系统中必须具备的一个关键特性。序列化的过程涉及将消息或数据转换为可以在网络上传输的格式，然后进行解码。有各种各样的序列化和反序列化数据的方式，最终取决于个人选择。

## 准备工作

你需要一个工作的 Windows 机器和 Visual Studio。不需要其他要求。

## 如何做…

在这个示例中，我们将看到序列化数据是多么容易。创建一个源文件，并从序列化类派生它：

```cpp
using namespace xmls;

class LastUsedDocument: public Serializable
{
public:
  LastUsedDocument();
  xString Name;
  xString Path;
  xInt Size;
};

class DatabaseLogin: public Serializable
{
public:
  DatabaseLogin();
  xString HostName;
  xInt Port;
  xString User;
  xString Password;
};

class SerialisationData: public Serializable
{
public:
  SerialisationData();
  xString Data1;
  xString Data2;
  xString Data3;
  xInt Data4;
  xInt Data5;
  xBool Data6;
  xBool Data7;
  DatabaseLogin Login;
  Collection<LastUsedDocument> LastUsedDocuments;
};

LastUsedDocument::LastUsedDocument()
{
  setClassName("LastUsedDocument");
  Register("Name", &Name);
  Register("Path", &Path);
  Register("Size", &Size);
};

DatabaseLogin::DatabaseLogin()
{
  setClassName("DatabaseLogin");
  Register("HostName", &HostName);
  Register("Port", &Port);
  Register("User", &User);
  Register("Password", &Password);
};

SerialisationData::SerialisationData()
{
  setClassName("SerialisationData");
  Register("Data1", &Data1);
  Register("Data2", &Data2);
  Register("Data3", &Data3);
  Register("Data4", &Data4);
  Register("Data5", &Data5);
  Register("Data6", &Data6);
  Register("Data7", &Data7);
  Register("Login", &Login);
  Register("LastUsedDocuments", &LastUsedDocuments);
  setVersion("2.1");
};

int main()
{
  // Creating the Datas object
  cout << "Creating object..." << endl;
  SerialisationData *Datas=new SerialisationData;
  Datas->Data1="This is the first string";
  Datas->Data2="This is the second random data";
  Datas->Data3="3rd data";
  Datas->Data4=1234;
  Datas->Data5=5678;
  Datas->Data6=false;
  Datas->Data7=true;
  Datas->Login.HostName="aws.localserver.something";
  Datas->Login.Port=2000;
  Datas->Login.User="packt.pub";
  Datas->Login.Password="PacktPassword";

  for (int docNum=1; docNum<=10; docNum++)
  {
    LastUsedDocument *doc = Datas->LastUsedDocuments.newElement();
    std::stringstream docName;
    docName << "Document #" << docNum;
    doc->Name = docName.str();
    doc->Path = "{FILEPATH}"; // Set Placeholder for search/replace
    doc->setVersion("1.1");
  }

  cout << "OK" << endl;

  // Serialize the Datas object
  cout << "Serializing object... " << endl;
  string xmlData = Datas->toXML();
  cout << "OK" << endl << endl;
  cout << "Result:" << endl;
  cout << xmlData << endl << endl;

  cout << "Login, URL:" << endl;
  cout << "Hostname: " << Datas->Login.HostName.value();
  cout << ":" << Datas->Login.Port.toString() << endl << endl;
  cout << "Show all collection items" << endl;
  for (size_t i=0; i<Datas->LastUsedDocuments.size(); i++)
  {
    LastUsedDocument* doc = Datas->LastUsedDocuments.getItem(i);
    cout << "Item " << i << ": " << doc->Name.value() << endl;
  }
  cout << endl;

  cout << "Deserialization:" << endl;
  cout << "Class version: " << Serializable::IdentifyClassVersion(xmlData) << endl;
  cout << "Performing deserialization..." << endl;

  // Deserialize the XML text
  SerialisationData* dser_Datas=new SerialisationData;
  if (Serializable::fromXML(xmlData, dser_Datas))
  {
    cout << "OK" << endl << endl;

    // compare both objects
    cout << "Compareing objects: ";
    if (dser_Datas->Compare(Datas))
      cout << "equal" << endl << endl; 
else
      cout << "net equal" << endl << endl;

    // now set value
    cout << "Set new value for field >password<..." << endl;
    dser_Datas->Login.Password = "newPassword";
    cout << "OK" << endl << endl;

    cout << "compare objects again: ";
    if (dser_Datas->Compare(Datas))
      cout << "equal" << endl << endl; else
      cout << "net equal" << endl << endl;

    cout << "search and replace placeholders: ";
    dser_Datas->Replace("{FILEPATH}", "c:\\temp\\");
    cout << "OK" << endl << endl;

    //output xml-data
    cout << "Serialize and output xml data: " << endl;
    cout << dser_Datas->toXML() << endl << endl;

    cout << "Clone object:" << endl;
    SerialisationData *clone1(new SerialisationData);
    Serializable::Clone(dser_Datas, clone1);
    cout << "Serialize and output clone: " << endl;
    cout << clone1->toXML() << endl << endl;
    delete (clone1);
  }
  delete(Datas);
  delete(dser_Datas);
  getchar();
  return 0;
}
```

## 它是如何工作的…

如前所述，序列化是将数据转换为可以传输的格式。我们可以使用 Google API，或者使用 JSON 格式或 YAML 来实现。在这个示例中，我们使用了最初由 Lothar Perr 编写的 XML 序列化器。原始源代码可以在[`www.codeproject.com/Tips/725375/Tiny-XML-Serialization-for-Cplusplus`](http://www.codeproject.com/Tips/725375/Tiny-XML-Serialization-for-Cplusplus)找到。程序的整个思想是将数据转换为 XML 格式。在可序列化数据类中，我们公开地从可序列化类派生它。我们创建一个构造函数来注册所有的数据元素，并创建我们想要序列化的不同数据元素。数据元素是`xString`类的类型。在构造函数中，我们注册每个数据元素。最后，从客户端，我们分配正确的数据进行发送，并使用 XML 序列化器类和 tinyxml 生成所需的 XML。最后，这个 XML 将被发送到网络上，并在接收时，将使用相同的逻辑进行解码。XML 有时被认为对游戏来说相当沉重和繁琐。

在这些情况下，建议使用 JSON。一些现代引擎，如 Unity3D 和虚幻引擎，已经内置了可以用来序列化数据的 JSON 解析器。然而，XML 仍然是一个重要的格式。我们的代码可能产生的一个可能的输出示例如下：

![它是如何工作的…](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/4929_11_04.jpg)

# 在游戏中使用套接字编程

套接字编程是最早用于在端到端连接之间传输数据的机制之一。即使现在，如果你习惯于编写套接字编程，它对于相对较小的游戏来说比使用第三方解决方案要好得多，因为它们会增加很多额外的空间。

## 准备工作

对于这个示例，你需要一个 Windows 机器和安装了 Visual Studio 的版本。

## 如何做…

在这个示例中，我们将发现编写套接字是多么容易：

```cpp
struct sockaddr_in
{
      short      sin_family;
      u_short      sin_port;
      struct      in_addr sin_addr;
      char      sin_zero[8];
};

int PASCAL connect(SOCKET,const struct sockaddr*,int);
    target.sin_family = AF_INET; // address family Internet
    target.sin_port = htons (PortNo); //Port to connect on
    target.sin_addr.s_addr = inet_addr (IPAddress); //Target IP

    s = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP); //Create socket
    if (s == INVALID_SOCKET)
    {
        return false; //Couldn't create the socket
    }
```

## 它是如何工作的…

当两个应用程序在不同的机器上进行通信时，通信通道的一端通常被描述为套接字。它是 IP 地址和端口的组合。当我们在不同的机器上使用信号或管道进行进程间通信时，就需要套接字。

**伯克利套接字**（**BSD**）是第一个开发的互联网套接字 API。它是在加利福尼亚大学伯克利分校开发的，并免费提供给 UNIX 的所有伯克利系统发行版，它存在于所有现代操作系统中，包括 UNIX 变体，如 OS X 和 Linux。Windows 套接字基于 BSD 套接字，并提供额外的功能以符合常规的 Windows 编程模型。Winsock2 是最新的 API。

常见的域有：

+   **AF UNIX**：这个地址格式是 UNIX 路径名

+   **AF INET**：这个地址格式是主机和端口号

各种协议可以以以下方式使用：

+   TCP/IP（虚拟电路）：SOCK_STREAM

+   UDP（数据报）：SOCK_DGRAM

这些是建立简单套接字连接的步骤：

1.  创建一个套接字。

1.  将套接字绑定到一个地址。

1.  等待套接字准备好进行输入/输出。

1.  从套接字读取和写入。

1.  重复从步骤 3 直到完成。

1.  关闭套接字。

这些步骤在这里通过示例进行了解释：

+   `int socket(domain, type, protocol)`：

参数`domain`应设置为`PF_INET`（协议族），而`type`是应该使用的连接类型。对于字节流套接字，使用`SOCK_STREAM`，而对于数据报（数据包）套接字，使用`SOCK_DGRAM`。`protocol`是正在使用的 Internet 协议。`SOCK_STREAM`通常会给出`IPPROTO_TCP`，而`SOCK_DGRAM`通常会给出`IPPROTO_UDP`。

+   `int sockfd;`

```cpp
sockfd = socket (PF_INET, SOCK_STREAM, 0):
```

`socket()`函数返回一个套接字描述符，供以后的系统调用使用，或者返回`-1`。当协议设置为`0`时，套接字会根据指定的类型选择正确的协议。

+   `int bind(int Socket, struct sockaddr *myAddress, int AddressLen )`

`bind()`函数将套接字绑定到本地地址。套接字是套接字描述符。`myAddress`是本地 IP 地址和端口。`AddressSize`参数给出地址的大小（以字节为单位），`bind()`在错误时返回`-1`。

+   `struct sockaddr_in {`

```cpp
  short int sin_family;     // set to AF_INET
  unsigned short int sin_port;   // Port number
  struct in_addr sin_addr;   // Internet address
  unsigned char sin_zero[8];   //set to all zeros
}
```

`struct sockaddr_in`是一个并行结构，它使得引用套接字地址的元素变得容易。`sin_port`和`sin_addr`必须以网络字节顺序表示。

# 发送数据

在正确设置了套接字之后，下一步是创建正确的服务器和客户端架构。发送数据非常简单，只涉及几行代码。

## 准备工作

要完成这个教程，你需要一台安装了 Visual Studio 的 Windows 机器。

## 如何做…

在这个教程中，我们将看到发送数据是多么容易：

```cpp
// Using the SendTo Function
#ifndef UNICODE
#define UNICODE
#endif

#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <Ws2tcpip.h>
#include <stdio.h>
#include <conio.h>

// Link with ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")

int main()
{

  int iResult;
  WSADATA wsaData;

  SOCKET SenderSocket = INVALID_SOCKET;
  sockaddr_in ReceiverAddress;

  unsigned short Port = 27015;

  char SendBuf[1024];
  int BufLen = 1024;

  //----------------------
  // Initialize Winsock
  iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
  if (iResult != NO_ERROR) {
    wprintf(L"WSAStartup failed with error: %d\n", iResult);
    return 1;

  }

  //---------------------------------------------
  // Create a socket for sending data
  SenderSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (SenderSocket == INVALID_SOCKET) {
    wprintf(L"socket failed with error: %ld\n", WSAGetLastError());
    WSACleanup();
    return 1;
  }
  //---------------------------------------------
  // Set up the ReceiverAddress structure with the IP address of
  // the receiver (in this example case "192.168.1.1")
  // and the specified port number.
  ReceiverAddress.sin_family = AF_INET;
  ReceiverAddress.sin_port = htons(Port);
  ReceiverAddress.sin_addr.s_addr = inet_addr("192.168.1.1");

  //---------------------------------------------
  // Send a datagram to the receiver
  wprintf(L"Sending a datagram to the receiver...\n");
  iResult = sendto(SenderSocket,
    SendBuf, BufLen, 0, (SOCKADDR *)& ReceiverAddress, sizeof(ReceiverAddress));
  if (iResult == SOCKET_ERROR) {
    wprintf(L"sendto failed with error: %d\n", WSAGetLastError());
    closesocket(SenderSocket);
    WSACleanup();
    return 1;
  }
  //---------------------------------------------
  // When the application is finished sending, close the socket.
  wprintf(L"Finished sending. Closing socket.\n");
  iResult = closesocket(SenderSocket);
  if (iResult == SOCKET_ERROR) {
    wprintf(L"closesocket failed with error: %d\n", WSAGetLastError());
    WSACleanup();
    return 1;
  }
  //---------------------------------------------
  // Clean up and quit.
  wprintf(L"Exiting.\n");
  WSACleanup();

  getch();
  return 0;
}

//Using the Send Function
#ifndef UNICODE
#define UNICODE
#endif

#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <Ws2tcpip.h>
#include <stdio.h>

// Link with ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT 27015

int main() {

  //----------------------
  // Declare and initialize variables.
  int iResult;
  WSADATA wsaData;

  SOCKET ConnectSocket = INVALID_SOCKET;
  struct sockaddr_in clientService;

  int recvbuflen = DEFAULT_BUFLEN;
  char *sendbuf = "Client: sending data test";
  char recvbuf[DEFAULT_BUFLEN] = "";

  //----------------------
  // Initialize Winsock
  iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
  if (iResult != NO_ERROR) {
    wprintf(L"WSAStartup failed with error: %d\n", iResult);
    return 1;
  }

  //----------------------
  // Create a SOCKET for connecting to server
  ConnectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (ConnectSocket == INVALID_SOCKET) {
    wprintf(L"socket failed with error: %ld\n", WSAGetLastError());
    WSACleanup();
    return 1;
  }

  //----------------------
  // The sockaddr_in structure specifies the address family,
  // IP address, and port of the server to be connected to.
  clientService.sin_family = AF_INET;
  clientService.sin_addr.s_addr = inet_addr("127.0.0.1");
  clientService.sin_port = htons(DEFAULT_PORT);

  //----------------------
  // Connect to server.
  iResult = connect(ConnectSocket, (SOCKADDR*)&clientService, sizeof(clientService));
  if (iResult == SOCKET_ERROR) {
    wprintf(L"connect failed with error: %d\n", WSAGetLastError());
    closesocket(ConnectSocket);
    WSACleanup();
    return 1;
  }

  //----------------------
  // Send an initial buffer
  iResult = send(ConnectSocket, sendbuf, (int)strlen(sendbuf), 0);
  if (iResult == SOCKET_ERROR) {
    wprintf(L"send failed with error: %d\n", WSAGetLastError());
    closesocket(ConnectSocket);
    WSACleanup();
    return 1;
  }

  printf("Bytes Sent: %d\n", iResult);

  // shutdown the connection since no more data will be sent
  iResult = shutdown(ConnectSocket, SD_SEND);
  if (iResult == SOCKET_ERROR) {
    wprintf(L"shutdown failed with error: %d\n", WSAGetLastError());
    closesocket(ConnectSocket);
    WSACleanup();
    return 1;
  }

  // Receive until the peer closes the connection
  do {

    iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
    if (iResult > 0)
      wprintf(L"Bytes received: %d\n", iResult);
    else if (iResult == 0)
      wprintf(L"Connection closed\n");
    else
      wprintf(L"recv failed with error: %d\n", WSAGetLastError());

  } while (iResult > 0);

  // close the socket
  iResult = closesocket(ConnectSocket);
  if (iResult == SOCKET_ERROR) {
    wprintf(L"close failed with error: %d\n", WSAGetLastError());
    WSACleanup();
    return 1;
  }

  WSACleanup();
  return 0;
}
```

## 工作原理…

用于在网络上通信的函数称为`sendto`。它声明为`int sendto(int sockfd, const void *msg, int len, int flags);`。

`sockfd`是你想要发送数据的套接字描述符（由`socket()`返回或从`accept()`获得），而`msg`是指向你想要发送的数据的指针。`len`是数据的长度（以字节为单位）。为了简单起见，我们现在可以将`flag`设置为`0`。`sendto()`返回实际发送的字节数（可能少于你告诉它发送的数量），或者在错误时返回`-1`。通过使用这个函数，你可以从一个连接点发送消息或数据到另一个连接点。这个函数可以用于使用内置的 Winsock 功能在网络上发送数据。`send`函数用于数据流，因此用于 TCP。如果我们要使用数据报和无连接协议，那么我们需要使用`sendto`函数。

# 接收数据

在正确设置了套接字并发送了数据之后，下一步是接收数据。接收数据非常简单，只涉及几行代码。

## 准备工作

要完成这个教程，你需要一台安装了 Visual Studio 的 Windows 机器。

## 如何做…

在这个教程中，我们将看到如何在网络上接收数据是多么容易。有两种方法可以做到这一点，一种是使用`recv`函数，另一种是使用`recvfrom`函数：

```cpp
#define WIN32_LEAN_AND_MEAN

#include <winsock2.h>
#include <Ws2tcpip.h>
#include <stdio.h>

// Link with ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")

#define DEFAULT_BUFLEN 512 
#define DEFAULT_PORT "27015"

int __cdecl main() {

  //----------------------
  // Declare and initialize variables.
  WSADATA wsaData;
  int iResult;

  SOCKET ConnectSocket = INVALID_SOCKET;
  struct sockaddr_in clientService;

  char *sendbuf = "this is a test";
  char recvbuf[DEFAULT_BUFLEN];
  int recvbuflen = DEFAULT_BUFLEN;

  //----------------------
  // Initialize Winsock
  iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
  if (iResult != NO_ERROR) {
    printf("WSAStartup failed: %d\n", iResult);
    return 1;
  }

  //----------------------
  // Create a SOCKET for connecting to server
  ConnectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (ConnectSocket == INVALID_SOCKET) {
    printf("Error at socket(): %ld\n", WSAGetLastError());
    WSACleanup();
    return 1;
  }

  //----------------------
  // The sockaddr_in structure specifies the address family,
  // IP address, and port of the server to be connected to.
  clientService.sin_family = AF_INET;
  clientService.sin_addr.s_addr = inet_addr("127.0.0.1");
  clientService.sin_port = htons(27015);

  //----------------------
  // Connect to server.
  iResult = connect(ConnectSocket, (SOCKADDR*)&clientService, sizeof(clientService));
  if (iResult == SOCKET_ERROR) {
    closesocket(ConnectSocket);
    printf("Unable to connect to server: %ld\n", WSAGetLastError());
    WSACleanup();
    return 1;
  }

  // Send an initial buffer
  iResult = send(ConnectSocket, sendbuf, (int)strlen(sendbuf), 0);
  if (iResult == SOCKET_ERROR) {
    printf("send failed: %d\n", WSAGetLastError());
    closesocket(ConnectSocket);
    WSACleanup();
    return 1;
  }

  printf("Bytes Sent: %ld\n", iResult);

  // shutdown the connection since no more data will be sent
  iResult = shutdown(ConnectSocket, SD_SEND);
  if (iResult == SOCKET_ERROR) {
    printf("shutdown failed: %d\n", WSAGetLastError());
    closesocket(ConnectSocket);
    WSACleanup();
    return 1;
  }

  // Receive until the peer closes the connection
  do {

    iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
    if (iResult > 0)
      printf("Bytes received: %d\n", iResult);
    else if (iResult == 0)
      printf("Connection closed\n");
    else
      printf("recv failed: %d\n", WSAGetLastError());

  } while (iResult > 0);

  // cleanup
  closesocket(ConnectSocket);
  WSACleanup();

  return 0;
}
```

## 工作原理…

就像`send`函数一样，只有一个函数用于在网络上接收数据，可以声明如下：

```cpp
int recv(int sockfd, void *buf,  int len, int flags);
```

`sockfd`是要从中读取的套接字描述符。下一个参数`buf`是要将信息读入的缓冲区，而`len`是缓冲区的最大长度。下一个参数`recv()`返回实际读入缓冲区的字节数，或者在错误时返回`-1`。如果`recv()`返回`0`，远程端已经关闭了连接。

使用这行代码，我们可以在网络上接收数据。如果数据在发送时被序列化，那么我们需要在这一点上对数据进行反序列化。这个过程将根据用于序列化数据的方法而有所不同。

# 处理延迟

网络游戏中经常出现的一个主要问题是延迟或卡顿。当两名玩家互相对战时，一方连接在高速网络上，另一方连接在非常低速的网络上，我们该如何更新数据呢？我们需要以一种方式更新数据，使得对两名玩家来说都看起来正常。没有玩家应该因为这种情况而获得不应有的优势。

## 准备工作

要完成这个配方，您需要一台运行 Windows 和 Visual Studio 的机器。

## 如何做到这一点…

在这个配方中，您将看到一些对抗延迟的技术。

通常，一个网络游戏会有以下更新循环。我们需要从循环结构中找出对抗延迟的最佳方法：

```cpp
read_network_messages()
    read_local_input()
    update_world()
    send_network_updates()
    render_world()
```

## 它是如何工作的…

在大多数电脑游戏中，当实施网络功能时，通常会选择特定类型的客户端-服务器架构。通常会选择一个有权威的服务器。这意味着服务器决定时间、结果和其他因素。客户端基本上是“愚蠢”的，它所做的一切都是基于来自服务器的数据进行模拟。现在让我们考虑两名玩家正在玩一款多人 FPS 游戏。其中一名玩家连接在高速网络上，另一名连接在低速网络上。因此，如果客户端依赖服务器进行更新，准确地在客户端渲染玩家的位置将会非常困难。假设`UserA`连接在高速网络上，而`UserB`连接在低速网络上。`UserA`向`UserB`开火。请注意，`UserA`和`UserB`也在世界空间中移动。我们如何计算子弹的位置和每个玩家的位置呢？如果我们准确地渲染来自服务器的信息，那将不准确，因为`UserA`在`UserB`收到更新之前可能已经移动到了新的位置。为了解决这个问题，通常有两种常用的解决方案。一种称为客户端预测。另一种方法进一步分为两种技术：插值和外推。请注意，如果计算机通过局域网连接，往返时间将是可以接受的。所有讨论的问题都集中在互联网上的网络连接。

在客户端预测中，客户端不再是“愚蠢”的，而是开始根据先前的移动输入来预测下一个位置和动画状态。最后，当它从服务器收到更新时，服务器将纠正错误，位置将被转换为当前接收到的位置。这种系统存在很多问题。如果预测错误，位置被更改为正确位置时会出现大的抖动。此外，让我们考虑声音和 VFX 效果。如果客户端`UserA`预测`UserB`正在行走并播放了脚步声音，后来服务器通知它`UserB`实际上在水中，我们该如何突然纠正这个错误呢？VFX 效果和状态也是如此。这种系统在许多*Quake*世界中被使用。

第二个系统有两个部分：外推和插值。在外推中，我们提前渲染。这在某种程度上类似于预测。它获取来自服务器的最后已知更新，然后在时间上向前模拟。因此，如果您落后 500 毫秒，并且您收到的最后更新是另一名玩家以每秒 300 个单位垂直于您的视图方向奔跑，那么客户端可以假设在“实时”中，玩家已经从他们最后已知的位置向前移动了 150 个单位。然后客户端可以在那个外推位置绘制玩家，本地玩家仍然可以更多或更少地瞄准另一名玩家。然而，这种系统的问题在于它很少会发生这样的情况。玩家的移动可能会改变，状态可能会改变，因此在大多数情况下应该避免使用这种系统。

在插值中，我们总是渲染过去的对象。例如，如果服务器每秒发送 25 次世界状态更新（确切地说），那么我们可能会在渲染中施加 40 毫秒的插值延迟。然后，当我们渲染帧时，我们在最后更新的位置和该位置之后的一个更新之间插值对象的位置。插值可以通过使用 C++中的内置 lerp 函数来完成。当对象到达最后更新的位置时，我们从服务器接收到新的更新（因为每秒 25 次更新意味着每 40 毫秒就会有更新），然后我们可以在接下来的 40 毫秒内开始朝着这个新位置移动。下图显示了来自服务器和客户端的碰撞箱位置的差异。

![它是如何工作的…](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/4929_11_05.jpg)

如果数据包在 40 毫秒后没有到达，也就是说，发生了数据包丢失，那么我们有两个选择。第一个选择是使用上面描述的方法进行外推。另一个选择是使玩家进入空闲状态，直到从服务器接收到下一个数据包。

# 使用同步模拟。

在多人游戏中，可能会有数百或数千台计算机同时连接。所有计算机的配置都不同。所有这些计算机的速度也会有所不同。因此，问题是，我们如何同步所有这些系统上的时钟，使它们都同步？

## 准备工作

要完成这个配方，你需要一台运行 Windows 和 Visual Studio 的机器。

## 如何做…

在这个配方中，我们将从理论角度看一下同步时钟的两种方法。

看一下以下伪代码：

+   方法 1

1.  向 `UserA` 发送一条消息。记录时间，直到他收到消息。

1.  向 `UserB` 发送一条消息。再次记录时间。

1.  基于值计算中位数，以决定更新时钟的时间，用于更新两台计算机的时钟。

+   方法 2

1.  让服务器进行大部分计算。

1.  让客户端进行一些本地计算。

1.  当客户端从服务器接收更新时，要么纠正错误，要么根据结果进行插值。

## 它是如何工作的…

当我们尝试同步时钟时，有两种方法。一种方法是服务器尝试找到一个中位时间来同步所有时钟。为了做到这一点，我们可以在游戏设计本身中包含机制。服务器需要找出每台客户机的响应时间，因此必须发送消息。这些消息可以是在准备好时按 *R*，或者在客户机上加载地图并且服务器记录时间。最后，当它从所有机器中获得了时间，它计算一个中位数，然后在那个时间更新所有机器的时钟。服务器发送给机器计算这个中位数的消息越多，它就会越准确。然而，这并不保证同步。

因此，一个更好的方法是服务器进行所有计算，客户端也进行一些本地计算，使用之前配方中描述的技术。最后，当服务器向客户端发送更新时，客户端可以纠正自己或进行插值以获得期望的结果。这是一个更好的结果，也是一个更好的系统。

# 使用兴趣区域过滤

当我们编写网络算法时，我们需要决定需要向服务器更新或从服务器更新的各种对象或状态。对象的数量越多，序列化和发送数据所需的时间就越长。因此，有必要对每帧需要更新的内容进行优先级排序，以及哪些对象可以等待更多周期进行更新。

## 准备工作

要完成这个配方，你需要一台运行 Windows 的机器。

## 如何做…

在这个配方中，我们将看到创建兴趣区域过滤有多么容易：

1.  创建场景中所有对象的列表。

1.  为每个对象添加一个表示其优先级的参数。

1.  基于优先级数字，将其传递给游戏的更新逻辑。

## 它是如何工作的...

在游戏中，我们需要按一定的优先级顺序定义对象。优先级顺序决定它们现在是否应该更新或稍后更新。需要优先处理的对象在很大程度上取决于游戏设计和一些研究。例如，在 FPS 游戏中，具有高优先级的对象将是用户当前瞄准的人物，附近的弹药，当然还有附近的敌人及其位置。在 RPG 或 RTS 的情况下可能会有所不同，因此它在不同游戏中肯定是不同的。

在为每个对象标记了优先级数字之后，我们可以告诉更新循环仅使用优先级为 1 和 2 的对象进行每帧更新，并使用优先级为 3 和 4 的对象进行延迟更新。这种结构也可以通过创建某种优先级队列来进行修改。从队列中，对象根据不同的更新逻辑弹出。较低优先级的对象也会同步，但在稍后的时间，而不是在当前帧中。

# 使用本地感知滤波器

这是网络游戏中对抗延迟的另一种方法。整个概念在数学上基于感知的概念。其基础是，如果对象在本地玩家的视图中正确更新和渲染，那么我们可以创造出一种逼真的幻觉，因此称为本地感知滤波器。

## 准备工作

要完成本教程，您需要一台运行 Windows 的计算机。

## 如何做到这一点...

在这个配方中，我们将了解实现子弹时间有多容易的理论概念。看一下以下伪代码：

1.  计算相对于玩家的本地速度。

1.  当子弹开始时加速它，并在它到达远程玩家时减速。

1.  从远程玩家的角度来看，子弹应该看起来以比正常速度更快的速度射出，然后减速到正常速度。

## 它是如何工作的...

本地感知滤波器也称为子弹时间，首次在电影《黑客帝国》中使用。从那时起，它们已经在各种游戏中使用。在单人模式中很容易实现；然而，在多人模式中，由于涉及减慢渲染，它变得更加复杂。基本上，该过程是在本地和远程玩家附近时增加和减少被动实体的速度。这是一种用于隐藏网络虚拟环境中的通信延迟的方法，并在《分布式虚拟环境的本地感知滤波器》中介绍，*P.M. Sharkey*，（第 242-249 页）。为简单起见，我们将本地玩家称为*p*，远程玩家称为*r*，而被动实体，如子弹，称为*e*。假设*d(i,j)*是延迟，*delta(i,j)*是距离，我们得到以下方程：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/4929_11_06.jpg)

以图形格式，可以通过查看以下图表来解释这一点。因此，就*p*而言，它在上坡时速度较慢，然后在下坡时速度较快。就*r*而言，它在顶部速度更快。

### 注意

该方法的一个主要限制是不能用于*瞬间命中*武器。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/4929_11_07.jpg)

问题在于当*e*到达*r*时，*p*对*e*的视图还没有到位，但是在*p*的视图中*e*会加速。为了解决这个问题，我们引入一个影子*r*，它缓冲了*p*对加速过程的视图。

添加缓冲后，我们将得到以下修订后的图表：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/4929_11_08.jpg)

所以在顶部，直到达到*r*之前不会加速，而在底部，它开始在位置*p*显示*e*。这也可以在以下网址查看演示：[`mikolalysenko.github.io/local-perception-filter-demo/`](http://mikolalysenko.github.io/local-perception-filter-demo/)。
