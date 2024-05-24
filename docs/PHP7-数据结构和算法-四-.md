# PHP7 数据结构和算法（四）

> 原文：[`zh.annas-archive.org/md5/eb90534f20ff388513beb1e54fb823ef`](https://zh.annas-archive.org/md5/eb90534f20ff388513beb1e54fb823ef)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：将图应用到实际中

图是用于解决各种现实问题的最有趣的数据结构之一。无论是在地图上显示方向，寻找最短路径，规划复杂的网络流量，寻找社交媒体中的个人资料之间的联系或推荐，我们都在处理图数据结构及其相关算法。图给我们提供了解决问题的许多方法，因此它们经常被用来解决复杂问题。因此，我们非常重要的是要理解图以及我们如何在解决方案中使用它们。

# 理解图的属性

图是通过边连接在一起的顶点或节点的集合。这些边可以是有序的或无序的，这意味着边可以有与之相关的方向，也可以是无向的，也称为双向边。我们使用集合*G*与顶点*V*和边*E*的关系来表示图，如下所示：

*G = (V, E)*

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00069.jpg)

在前面的图中，我们有五个顶点和六条边：

*V = {A, B, C, D, E}*

*E = {AB, AC, AD, BD, BE, CD, DE}*

如果我们考虑前面的图，A 和 B 之间的连接可以表示为 AB 或 BA，因为我们没有定义连接的方向。图和树数据结构之间的一个重要区别是，图可以形成循环，但树数据结构不能。与树数据结构不同，我们可以从图数据结构中的任何顶点开始。此外，我们可以在任何两个顶点之间有直接的边，而在树中，只有在子节点是父节点的直接后代时，两个节点才能连接。

图有不同的属性和与之相关的关键词。在继续讨论图及其应用之前，我们将探讨这些术语。

# 顶点

图中的每个节点称为一个顶点。通常，顶点表示为一个圆。在我们的图中，节点 A，B，C，D 和 E 是顶点。

# 边

边是两个顶点之间的连接。通常，它由两个顶点之间的线表示。在前面的图中，我们在 A 和 B 之间，A 和 C 之间，A 和 D 之间，B 和 D 之间，C 和 D 之间，B 和 E 之间，以及 D 和 E 之间有边。我们可以表示边为 AB 或（A，B）。边可以有三种类型：

+   **有向边**：如果一条边标有箭头，那么它表示一条有向边。有向边是单向的。箭头的头部是终点，箭头的尾部是起点：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00070.gif)

在前面的图中，我们可以看到 A 有一个指向 B 的有向边，这意味着 A，B 是一条边，但反之不成立（B，A）。因此，这是一个单向边或有向边的例子。

+   无向边：无向边是两个顶点之间没有方向的连接。这意味着边满足双向关系。下图是无向图的一个例子，其中 A 与 B 连接的方式是（A，B）和（B，A）是相同的：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00071.jpg)

+   **加权边**：当一条边携带额外信息，如成本、距离或其他信息时，我们称该边为加权边。这用于许多图算法。在下图中，边（A，B）的权重为 5。根据图的定义，这可以是距离、成本或其他任何东西：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00072.gif)

# 邻接

如果两个顶点之间有一条边，则它们是相邻的。如果顶点 A 和 B 之间有直接的边，则它们被称为相邻。在下图中，我们可以看到顶点 1 和顶点 2 通过边 e1 相连，因此它们被称为相邻。由于顶点 2 与顶点 3 和 4 之间没有边，所以顶点 2 不与顶点 3 和顶点 4 相邻。

# 关联

如果顶点是边的端点之一，则边与顶点相关。此外，如果两条边共享一个顶点，则两条边是相关的。如果考虑下图，我们可以看到边(e1，e2)，(e2，e3)和(e1，e3)共享顶点 1。我们还有边(e3，e4)共享顶点 4，以及边(e2，e4)共享顶点 3。类似地，我们可以说顶点 1 与边 e1，e2 和 e3 相关，顶点 2 与边 e1 相关，顶点 3 与边 e2 和 e4 相关，顶点 4 与边 e3 和 e4 相关：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00073.jpg)

# 入度和出度

特定顶点的入边总数称为该顶点的入度，特定顶点的出边总数称为该顶点的出度。如果考虑下图的有向边，我们可以说顶点 A 的入度为 0，出度为 1，顶点 B 的入度为 2，出度为 1，顶点 C 的入度为 1，出度为 1，顶点 D 的入度为 1，出度为 1，顶点 E 的入度为 1，出度为 2，最后，顶点 F 的入度为 1，出度为 0。

# 路径

路径是从起始顶点到我们试图到达的另一个顶点的顶点和边的序列。在下图中，从 A 到 F 的路径由(A，B)，(B，C)，(C，E)和(E，F)表示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00074.gif)

# 图的类型

根据它们的绘制或表示方式，有不同类型的图可用。每种类型的图都有不同的行为和用途。我们将重点讨论四种主要类型的图。

# 有向图

如果图只包含有向边，则图称为有向图。有向图也称为有向图或有向网络。下图表示了一个有向图。这里，(A，B)，(B，C)，(C，E)，(E，D)，(E，F)和(D，B)边是有向边。由于边是有向的，边 AB 与边 BA 不同：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00075.gif)

# 无向图

如果图只包含无向边，则图是无向图。换句话说，无向图中的边是双向的。有时，无向图也被称为无向网络。在无向图中，如果顶点 A 连接到顶点 B，则假定(A，B)和(B，A)表示相同的边。下图显示了一个无向图的示例，其中所有边都没有箭头表示方向：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00076.jpg)

# 加权图

如果图的所有边都是加权边，则图称为加权图。我们将在接下来的部分中详细讨论加权图。加权图可以是有向图或无向图。每条边必须有一个与之关联的值。边的权重总是被称为边的成本。下图表示了一个具有五个顶点和七条边的无向加权图。这里，顶点 1 和 2 之间的边的权重为 2，顶点 1 和 4 之间的边的权重为 5，顶点 4 和 5 之间的边的权重为 58：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00077.jpg)

# 有向无环图（DAG）

无环图是一种没有循环或环路的图。如果我们想从特定节点访问其他节点，我们不会访问任何节点两次。有向无环图，通常称为 DAG，是一个无环的有向图。有向无环图在图算法中有许多用途。有向无环图具有拓扑排序，其中顶点的排序使得每条边的起始端点在排序中出现在边的结束端点之前。以下图表示一个 DAG：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00078.jpg)

乍一看，似乎 B，C，E 和 D 形成一个循环，但仔细观察表明它们并没有形成循环，而我们在有向图部分使用的示例是循环图的完美示例。

# 在 PHP 中表示图

由于图是由顶点和边表示的，我们必须考虑两者来表示图。表示图的方法有几种，但最流行的方法如下：

+   邻接表

+   邻接矩阵

# 邻接表

我们可以使用链表表示图，其中一个数组将用于顶点，每个顶点将有一个链表，表示相邻顶点之间的边。当以邻接表表示时，示例图如下：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00079.jpg)

# 邻接矩阵

在邻接矩阵中，我们使用二维数组表示图，其中每个节点在水平和垂直方向上表示数组索引。如果从 A 到 B 的边是有方向的，则将该数组索引[A][B]标记为 1 以标记连接；否则为 0。如果边是无方向的，则[A][B]和[B][A]都设置为 1。如果图是加权图，则[A][B]或[B][A]将存储权重而不是 1。以下图显示了使用矩阵表示的无向图表示： 

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00080.jpg)

这个图显示了矩阵的有向图表示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00081.jpg)

虽然我们的图表示显示了邻接表和矩阵中数组索引的字母表示，但我们也可以使用数字索引来表示顶点。

# 重新讨论图的 BFS 和 DFS

我们已经看到了如何在树结构中实现广度优先搜索（BFS）和深度优先搜索（DFS）。我们将重新讨论我们的 BFS 和 DFS 用于图。树实现和图实现之间的区别在于，在图实现中，我们可以从任何顶点开始，而在树数据结构中，我们从树的根开始。另一个重要的考虑因素是，我们的图可以有循环，而树中没有循环，因此我们不能重新访问一个节点或顶点，否则会陷入无限循环。我们将使用一个称为图着色的概念，其中我们使用颜色或值来保持不同节点访问的状态，以保持简单。现在让我们编写一些代码来实现图中的 BFS 和 DFS。

# 广度优先搜索

现在我们将实现图的 BFS。考虑以下无向图，首先，我们需要用矩阵或列表表示图。为了简单起见，我们将使用邻接矩阵表示图：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00082.jpg)

前面的邻接图有六个顶点，顶点从 1 到 6 标记（没有 0）。由于我们的顶点编号，我们可以将它们用作数组索引以加快访问速度。我们可以构建图如下：

```php
$graph = []; 

$visited = []; 

$vertexCount = 6; 

for($i = 1;$i<=$vertexCount;$i++) { 

    $graph[$i] = array_fill(1, $vertexCount, 0); 

    $visited[$i] = 0; 

} 

```

在这里，我们有两个数组，一个用于表示实际图形，另一个用于跟踪已访问的节点。我们希望确保我们不会多次访问一个节点，因为这可能会导致无限循环。由于我们的图形有六个顶点，我们将`$vertexCount`保持为`6`。然后，我们将图数组初始化为具有初始值`0`的二维数组。我们将从数组的索引`1`开始。我们还将通过将每个顶点分配给`$visited`数组中的`0`来设置每个顶点为未访问状态。现在，我们将在我们的图形表示中添加边。由于图是无向的，我们需要为每条边设置两个属性。换句话说，我们需要为标记为 1 和 2 的顶点之间的边设置双向边值，因为它们之间共享一条边。以下是先前图形的完整表示的代码：

```php
$graph[1][2] = $graph[2][1] = 1; 

$graph[1][5] = $graph[5][1] = 1; 

$graph[5][2] = $graph[2][5] = 1; 

$graph[5][4] = $graph[4][5] = 1; 

$graph[4][3] = $graph[3][4] = 1; 

$graph[3][2] = $graph[2][3] = 1; 

$graph[6][4] = $graph[4][6] = 1; 

```

因此，我们已经使用邻接矩阵表示了图。现在，让我们为矩阵定义 BFS 算法：

```php
function BFS(array &$graph, int $start, array $visited): SplQueue { 

    $queue = new SplQueue;

    $path = new SplQueue;

    $queue->enqueue($start);

    $visited[$start] = 1;

    while (!$queue->isEmpty()) { 

      $node = $queue->dequeue();

      $path->enqueue($node);

      foreach ($graph[$node] as $key => $vertex) { 

          if (!$visited[$key] && $vertex == 1) { 

          $visited[$key] = 1;

          $queue->enqueue($key);

          }

      }

    }

    return $path;

}

```

我们实现的 BFS 函数接受三个参数：实际图形、起始顶点和空的已访问数组。我们本可以避免第三个参数，并在 BFS 函数内部进行初始化。归根结底，我们可以选择任一种方式来完成这一点。在我们的函数实现中，有两个队列：一个用于保存我们需要访问的节点，另一个用于保存已访问节点的顺序，或者搜索的路径。在函数结束时，我们返回路径队列。

在函数内部，我们首先将起始节点添加到队列中。然后，我们从该节点开始访问其相邻节点。如果节点未被访问并且与当前节点有连接，则将其添加到我们的访问队列中。我们还将当前节点标记为已访问，并将其添加到我们的路径中。现在，我们将使用我们构建的图矩阵和一个访问节点来调用我们的 BFS 函数。以下是执行 BFS 功能的程序：

```php
$path = BFS($graph, 1, $visited); 

while (!$path->isEmpty()) { 

    echo $path->dequeue()."\t"; 

} 

```

从前面的代码片段中可以看出，我们从节点 1 开始搜索。输出将如下所示：

```php
    1       2       5       3       4       6

```

如果我们将`BFS`函数调用的第二个参数从 1 更改为 5 作为起始节点，那么输出将如下所示：

```php
    5       1       2       4       3       6

```

# 深度优先搜索

正如我们在 BFS 中看到的那样，我们也可以为 DFS 定义任何起始顶点。不同之处在于，对于已访问节点的列表，我们将使用堆栈而不是队列。代码的其他部分将类似于我们的 BFS 代码。我们还将使用与 BFS 实现相同的图。我们将实现的 DFS 是迭代的。以下是其代码：

```php
function DFS(array &$graph, int $start, array $visited): SplQueue { 

    $stack = new SplStack; 

    $path = new SplQueue; 

    $stack->push($start); 

    $visited[$start] = 1; 

    while (!$stack->isEmpty()) { 

      $node = $stack->pop(); 

      $path->enqueue($node); 

      foreach ($graph[$node] as $key => $vertex) { 

          if (!$visited[$key] && $vertex == 1) { 

          $visited[$key] = 1; 

          $stack->push($key); 

          } 

      } 

    } 

    return $path; 

} 

```

如前所述，对于 DFS，我们必须使用堆栈而不是队列，因为我们需要从堆栈中获取最后一个顶点，而不是第一个（如果我们使用了队列）。对于路径部分，我们使用队列，以便在显示过程中按顺序显示路径。以下是调用我们的图`$graph`的代码：

```php
$path = DFS($graph, 1, $visited); 

while (!$path->isEmpty()) { 

    echo $path->dequeue()."\t"; 

} 

```

该代码将产生以下输出：

```php
    1       5       4       6       3       2

```

对于上述示例，我们从顶点 1 开始，并首先访问顶点 5，这是顶点 1 的两个相邻顶点中标记为 5 和 2 的顶点之一。现在，顶点 5 有两个标记为 4 和 2 的顶点。顶点 4 将首先被访问，因为它是从顶点 5 出发的第一条边（记住我们从左到右访问节点的方向）。接下来，我们将从顶点 4 访问顶点 6。由于我们无法从顶点 6 继续前进，它将返回到顶点 4 并访问标记为 3 的未访问相邻顶点。当我们到达顶点 3 时，有两个相邻顶点可供访问。它们被标记为顶点 4 和顶点 2。我们之前已经访问了顶点 4，因此无法重新访问它，我们必须从顶点 3 访问顶点 2。由于顶点 2 有三个顶点，分别是顶点 3、5 和 1，它们都已经被访问，因此我们实际上已经完成了 DFS 的实现。

如果我们从一个起始顶点寻找特定的终点顶点，我们可以传递一个额外的参数。在之前的例子中，我们只是获取相邻的顶点并访问它们。对于特定的终点顶点，我们需要在 DFS 算法的迭代过程中将目标顶点与我们访问的每个顶点进行匹配。

# 使用 Kahn 算法进行拓扑排序

假设我们有一些任务要做，每个任务都有一些依赖关系，这意味着在执行实际任务之前，应该先完成依赖的任务。当任务和依赖之间存在相互关系时，问题就出现了。现在，我们需要找到一个合适的顺序来完成这些任务。我们需要一种特殊类型的排序，以便在不违反完成任务的规则的情况下对这些相互关联的任务进行排序。拓扑排序将是解决这类问题的正确选择。在拓扑排序中，从顶点 A 到 B 的有向边 AB 被排序，以便 A 始终在排序中位于 B 之前。这将适用于所有的顶点和边。应用拓扑排序的另一个重要因素是图必须是一个 DAG。任何 DAG 都至少有一个拓扑排序。大多数情况下，对于给定的图，可能存在多个拓扑排序。有两种流行的算法可用于拓扑排序：Kahn 算法和 DFS 方法。我们将在这里讨论 Kahn 算法，因为我们在本书中已经多次讨论了 DFS。

Kahn 算法有以下步骤来从 DAG 中找到拓扑排序：

1.  计算每个顶点的入度（入边），并将所有入度为 0 的顶点放入队列中。还要将访问节点的计数初始化为 0。

1.  从队列中移除一个顶点，并对其执行以下操作：

1. 将访问节点计数加 1。

2. 将所有相邻顶点的入度减 1。

3. 如果相邻顶点的入度变为 0，则将其添加到队列中。

1.  重复*步骤 2*，直到队列为空。

1.  如果访问节点的计数与节点的计数不同，则给定 DAG 的拓扑排序是不可能的。

让我们考虑以下图。这是一个 DAG 的完美例子。现在，我们想使用拓扑排序和 Kahn 算法对其进行排序：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00083.jpg)

现在让我们使用邻接矩阵来表示这个图，就像我们之前为其他图所做的那样。矩阵将如下所示：

```php
$graph = [ 

    [0, 0, 0, 0, 1], 

    [1, 0, 0, 1, 0], 

    [0, 1, 0, 1, 0], 

    [0, 0, 0, 0, 0], 

    [0, 0, 0, 0, 0], 

];

```

现在，我们将按照我们定义的步骤实现 Kahn 算法。以下是它的实现：

```php
function topologicalSort(array $matrix): SplQueue { 

    $order = new SplQueue; 

    $queue = new SplQueue; 

    $size = count($matrix); 

    $incoming = array_fill(0, $size, 0); 

    for ($i = 0; $i < $size; $i++) { 

      for ($j = 0; $j < $size; $j++) { 

          if ($matrix[$j][$i]) { 

          $incoming[$i] ++; 

          } 

      } 

      if ($incoming[$i] == 0) { 

          $queue->enqueue($i); 

      } 

    } 

    while (!$queue->isEmpty()) { 

      $node = $queue->dequeue(); 

      for ($i = 0; $i < $size; $i++) { 

          if ($matrix[$node][$i] == 1) { 

            $matrix[$node][$i] = 0; 

            $incoming[$i] --; 

            if ($incoming[$i] == 0) { 

                $queue->enqueue($i); 

            } 

          } 

      } 

      $order->enqueue($node); 

    } 

    if ($order->count() != $size) // cycle detected 

      return new SplQueue; 

    return $order; 

} 

```

从前面的实现中可以看出，我们实际上考虑了我们提到的 Kahn 算法的每一步。我们首先找到了顶点的入度，并将入度为 0 的顶点放入了队列中。然后，我们检查了队列的每个节点，并减少了相邻顶点的入度，并再次将任何入度为 0 的相邻顶点添加到队列中。最后，我们返回了排序后的队列，或者如果有序顶点的计数与实际顶点的计数不匹配，则返回一个空队列。现在，我们可以调用该函数来返回排序后的顶点列表作为队列。以下是执行此操作的代码：

```php
$sorted = topologicalSort($graph);

while (!$sorted->isEmpty()) {

    echo $sorted->dequeue() . "\t";

} 

```

现在，这将遍历队列中的每个元素并将它们打印出来。输出将如下所示：

```php
    2       1       0 

      3       4

```

输出符合我们的期望。从之前的图表中可以看出，顶点 **2** 直接连接到顶点 **1** 和顶点 **3** ，顶点 **1** 直接连接到顶点 **0** 和顶点 **3** 。由于顶点 **2** 没有入边，我们将从顶点 **2** 开始进行拓扑排序。顶点 **1** 有一个入边，顶点 **3** 有两个入边，所以在顶点 **2** 之后，我们将按照算法访问顶点 **1** 。相同的原则将带我们到顶点 **0** ，然后是顶点 **3** ，最后是顶点 **4** 。我们还必须记住对于给定的图，可能存在多个拓扑排序。Kahn 算法的复杂度是 **O** (*V+E* )，其中 **V** 是顶点的数量，**E** 是边的数量。

# 使用 Floyd-Warshall 算法的最短路径

披萨外卖公司的常见情景是尽快送达披萨。图算法可以帮助我们在这种情况下。Floyd-Warshall 算法是一种非常常见的算法，用于找到从 u 到 v 的最短路径，使用所有顶点对(u, v)。最短路径表示两个相互连接的节点之间的最短可能距离。用于计算最短路径的图必须是加权图。在某些情况下，权重也可以是负数。该算法非常简单，也是最容易实现的之一。它在这里显示：

```php
for i:= 1 to n do 

  for j:= 1 to n do 

     dis[i][j] = w[i][j] 

for k:= 1 to n do 

   for i:= 1 to n do 

      for j:= 1 to n do 

         sum := dis[i][k] + dis[k][j] 

         if (sum < dis[i][j]) 

              dis[i][j] := sum 

```

首先，我们将每个权重复制到一个成本或距离矩阵中。然后，我们遍历每个顶点，并计算从顶点 `i` 经过顶点 `k` 到达顶点 `j` 的成本或距离。如果距离或成本小于顶点 `i` 到顶点 `j` 的直接路径，我们选择路径 `i` 到 `k` 到 `j` 而不是直接路径 `i` 到 `j` 。让我们考虑以下图表：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00084.gif)

在这里，我们可以看到一个带有每条边权重的无向图。现在，如果我们寻找从 **A** 到 **E** 的最短路径，那么我们有以下选项：

+   **A** 到 **E** 通过 **B** 的距离为 **20**

+   **A** 到 **E** 通过 **D** 的距离为 **25**

+   **A** 到 **E** 通过 **D** 和 **B** 的距离为 **20**

+   **A** 到 **E** 通过 **B** 和 **D** 的距离为 **35**

因此，我们可以看到最小距离是 **20** 。现在，让我们以数值表示顶点，以编程方式实现这一点。我们将使用 0、1、2、3 和 4 代替 A、B、C、D 和 E。现在，让我们用邻接矩阵格式表示之前的图：

```php
$totalVertices = 5; 

$graph = []; 

for ($i = 0; $i < $totalVertices; $i++) { 

    for ($j = 0; $j < $totalVertices; $j++) { 

      $graph[$i][$j] = $i == $j ? 0 : PHP_INT_MAX; 

    }

}

```

在这里，我们采取了不同的方法，并将所有边初始化为 PHP 整数的最大值。这样做的原因是确保非边的值为 0 不会影响算法逻辑，因为我们正在寻找最小值。现在，我们需要像之前的图表中显示的那样向图中添加权重：

```php
$graph[0][1] = $graph[1][0] = 10;

$graph[2][1] = $graph[1][2] = 5;

$graph[0][3] = $graph[3][0] = 5;

$graph[3][1] = $graph[1][3] = 5;

$graph[4][1] = $graph[1][4] = 10;

$graph[3][4] = $graph[4][3] = 20;

```

由于这是一个无向图，我们给两条边分配相同的值。如果是有向图，我们只能为每个权重制作一次输入。现在，是时候实现 Floyd-Warshall 算法，以找到任意一对节点的最短路径。这是我们对该函数的实现：

```php
function floydWarshall(array $graph): array {

    $dist = [];

    $dist = $graph;

    $size = count($dist);

    for ($k = 0; $k < $size; $k++)

      for ($i = 0; $i < $size; $i++)

          for ($j = 0; $j < $size; $j++)

        $dist[$i][$j] = min($dist[$i][$j],

    $dist[$i][$k] + $dist[$k][$j]);

    return $dist;

} 

```

正如我们之前提到的，实现非常简单。我们有三个内部循环来计算最小距离，并且在函数结束时返回距离数组。现在，让我们调用这个函数并检查我们的预期结果是否匹配：

```php
$distance = floydWarshall($graph); 

echo "Shortest distance between A to E is:" . $distance[0][4] . "\n"; 

echo "Shortest distance between D to C is:" . $distance[3][2] . "\n"; 

```

以下是代码的输出：

```php
Shortest distance between A to E is:20

Shortest distance between D to C is:10

```

如果我们检查之前的图表，我们可以看到 **D** 和 **C** 之间的最短距离实际上是 **10** ，路径是 D → B → C (5+5)，这是所有可能路线中的最短距离 (D → A → B → C (20)，或 D → E → B → C (35))。

Floyd-Warshall 算法的复杂度为 **O** (*V3* )，其中 **V** 是图中顶点的数量。现在我们将探讨另一个以找到单源最短路径而闻名的算法。

# 使用 Dijkstra 算法的单源最短路径

我们可以很容易地使用 Floyd-Warshall 算法找到最短路径，但我们无法得到从节点 X 到 Y 的实际路径。这是因为 Floyd-Warshall 算法计算距离或成本，不存储最小成本的实际路径。例如，使用 Google 地图，我们总是可以找到从任何给定位置到目的地的路线。Google 地图可以显示最佳路线，关于距离、旅行时间或其他因素。这是单源最短路径算法使用的完美例子。有许多算法可以找到单源最短路径问题的解决方案；然而，Dijkstra 最短路径算法是最流行的。有许多实现 Dijkstra 算法的方法，例如使用斐波那契堆、最小堆、优先队列等。每种实现都有其自身的优势，关于 Dijkstra 解决方案的性能和改进。让我们来看一下算法的伪代码：

```php
   function Dijkstra(Graph, source):

      create vertex set Q

      for each vertex v in Graph:   

          dist[v] := INFINITY

          prev[v] := UNDEFINED          

          add v to Q         

      dist[source] := 0           

      while Q is not empty:

          u := vertex in Q with min dist[u]

          remove u from Q

          for each neighbor v of u:

              alt := dist[u] + length(u, v)

              if alt < dist[v]:   

                  dist[v] := alt

                  prev[v] := u

      return dist[], prev[]

```

现在，我们将使用优先队列来实现算法。首先，让我们选择一个图来实现算法。我们可以选择以下无向加权图。它有六个节点，节点和顶点之间有许多连接。首先，我们需要用邻接矩阵表示以下图：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00085.jpg)

从前面的图表中可以看出，我们的顶点用字母**A**到**F**标记，因此我们将使用顶点名称作为 PHP 关联数组中的键：

```php
$graph = [

    'A' => ['B' => 3, 'C' => 5, 'D' => 9],

    'B' => ['A' => 3, 'C' => 3, 'D' => 4, 'E' => 7],

    'C' => ['A' => 5, 'B' => 3, 'D' => 2, 'E' => 6, 'F' => 3],

    'D' => ['A' => 9, 'B' => 4, 'C' => 2, 'E' => 2, 'F' => 2],

    'E' => ['B' => 7, 'C' => 6, 'D' => 2, 'F' => 5],

    'F' => ['C' => 3, 'D' => 2, 'E' => 5],

];

```

现在，我们将使用优先队列来实现 Dijkstra 算法。我们将使用我们为上一个图表创建的邻接矩阵来找到从源顶点到目标顶点的路径。我们的 Dijkstra 算法将返回一个数组，其中包括两个节点之间的最小距离和所遵循的路径。我们将路径返回为一个栈，以便我们可以按相反顺序获取实际路径。以下是实现：

```php
function Dijkstra(array $graph, string $source,string $target):array{ 

    $dist = []; 

    $pred = []; 

    $Queue = new SplPriorityQueue(); 

    foreach ($graph as $v => $adj) { 

      $dist[$v] = PHP_INT_MAX; 

      $pred[$v] = null; 

      $Queue->insert($v, min($adj)); 

    } 

    $dist[$source] = 0; 

    while (!$Queue->isEmpty()) { 

      $u = $Queue->extract(); 

      if (!empty($graph[$u])) { 

          foreach ($graph[$u] as $v => $cost) { 

           if ($dist[$u] + $cost < $dist[$v]) { 

            $dist[$v] = $dist[$u] + $cost; 

            $pred[$v] = $u; 

        } 

          } 

      } 

    } 

    $S = new SplStack();

    $u = $target; 

    $distance = 0;

    while (isset($pred[$u]) && $pred[$u]) {

      $S->push($u);

      $distance += $graph[$u][$pred[$u]];

      $u = $pred[$u]; 

    } 

    if ($S->isEmpty()) { 

      return ["distance" => 0, "path" => $S]; 

    } else {

      $S->push($source);

      return ["distance" => $distance, "path" => $S]; 

    }

}

```

从前面的实现中可以看出，首先，我们创建了两个数组来存储距离和前任，以及优先队列。然后，我们将每个顶点设置为 PHP 的最大整数（`PHP_INT_MAX`）值（伪代码中的 INFINITY）和前任为`NULL`。我们还取了所有相邻节点的最小值并将它们存储在队列中。循环结束后，我们将源节点的距离设置为`0`。然后我们检查队列中的每个节点，并检查最近的邻居以找到最小路径。如果使用`if ($dist[$u] + $cost < $dist[$v])`找到了路径，我们将其分配给该顶点。

然后我们创建了一个名为`$s`的栈来存储路径。我们从目标顶点开始，访问相邻的顶点以到达源顶点。当我们通过相邻的顶点移动时，我们还计算了通过访问这些顶点所覆盖的距离。由于我们的函数返回了距离和路径，我们构造了一个数组来返回给定图、源和目标的距离和路径。如果没有路径存在，我们将返回距离为 0，并返回一个空栈作为输出。现在，我们将写几行代码来使用图`$graph`和函数`Dijkstra`来检查我们的实现：

```php
$source = "A"; 

$target = "F"; 

$result = Dijkstra($graph, $source, $target); 

extract($result); 

echo "Distance from $source to $target is $distance \n"; 

echo "Path to follow : "; 

while (!$path->isEmpty()) { 

    echo $path->pop() . "\t"; 

} 

```

如果我们运行这段代码，它将在命令行中输出以下内容：

```php
Distance from A to F is 8

Path to follow : A      C       F

```

输出看起来完全正确，从图表中我们可以看到从**A**到**F**的最短路径是通过**C**，最短距离是*5 + 3 = 8*。

Dijkstra 算法的运行复杂度为**O**(*V2*)。由于我们使用了最小优先队列，运行时复杂度为**O**(*E + V log V*)。

# 使用 Bellman-Ford 算法找到最短路径

尽管 Dijkstra 算法是最流行和高效的用于找到单源最短路径的算法，但它没有解决一个问题。如果图中有一个负循环，Dijkstra 算法无法检测到负循环，因此它无法工作。负循环是一个循环，其中所有边的总和为负。如果一个图包含一个负循环，那么找到最短路径将是不可能的，因此在寻找最短路径时解决这个问题是很重要的。这就是为什么我们使用 Bellman-Ford 算法，尽管它比 Dijkstra 算法慢。以下是 Bellman-Ford 算法寻找最短路径的算法伪代码：

```php
function BellmanFord(list vertices, list edges, vertex source) 

  // This implementation takes a vertex source 

  // and fills distance array with shortest-path information 

  // Step 1: initialize graph 

  for each vertex v in vertices: 

    if v is source 

      distance[v] := 0 

    else 

      distance[v] := infinity 

  // Step 2: relax edges repeatedly 

  for i from 1 to size(vertices)-1: 

    for each edge (u, v) with weight w in edges: 

      if distance[u] + w < distance[v]: 

        distance[v] := distance[u] + w 

  // Step 3: check for negative-weight cycles 

    for each edge (u, v) with weight w in edges: 

        if distance[u] + w < distance[v]: 

      error "Graph contains a negative-weight cycle" 

```

我们可以看到 Bellman-Ford 算法在寻找节点之间的最短路径时也考虑了边和顶点。这被称为松弛过程，在 Dijkstra 算法中也使用。图算法中的松弛过程是指如果通过*V*的路径包括*V*，则更新与顶点*V*连接的所有顶点的成本。简而言之，松弛过程试图通过另一个顶点降低到达一个顶点的成本。现在，我们将为我们在 Dijkstra 算法中使用的相同图实现这个算法。唯一的区别是这里我们将为我们的节点和顶点使用数字标签：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00086.jpg)

现在是时候以邻接矩阵格式表示图了。以下是 PHP 中的矩阵：

```php
$graph = [ 

    0 => [0, 3, 5, 9, 0, 0], 

    1 => [3, 0, 3, 4, 7, 0], 

    2 => [5, 3, 0, 2, 6, 3], 

    3 => [9, 4, 2, 0, 2, 2], 

    4 => [0, 7, 6, 2, 0, 5], 

    5 => [0, 0, 3, 2, 5, 0] 

]; 

```

以前，我们使用值 0 表示两个顶点之间没有边。如果我们在这里做同样的事情，那么在松弛过程中，取两条边中的最小值，其中一条代表 0，将始终产生 0，这实际上意味着两个顶点之间没有连接。因此，我们必须选择一个更大的数字来表示不存在的边。我们可以使用 PHP 的`MAX_INT_VALUE`常量来表示这些边，以便这些不存在的边不被考虑。这可以成为我们新的图表示：

```php
define("I", PHP_INT_MAX); 

$graph = [ 

    0 => [I, 3, 5, 9, I, I], 

    1 => [3, I, 3, 4, 7, I], 

    2 => [5, 3, I, 2, 6, 3], 

    3 => [9, 4, 2, I, 2, 2], 

    4 => [I, 7, 6, 2, I, 5], 

    5 => [I, I, 3, 2, 5, I] 

]; 

```

现在，让我们为 Bellman-Ford 算法编写实现。我们将使用在伪代码中定义的相同方法：

```php
function bellmanFord(array $graph, int $source): array { 

    $dist = []; 

    $len = count($graph); 

    foreach ($graph as $v => $adj) { 

      $dist[$v] = PHP_INT_MAX; 

    } 

    $dist[$source] = 0; 

    for ($k = 0; $k < $len - 1; $k++) { 

      for ($i = 0; $i < $len; $i++) { 

          for ($j = 0; $j < $len; $j++) { 

            if ($dist[$i] > $dist[$j] + $graph[$j][$i]) { 

            $dist[$i] = $dist[$j] + $graph[$j][$i]; 

        } 

          } 

      } 

    } 

    for ($i = 0; $i < $len; $i++) { 

      for ($j = 0; $j < $len; $j++) { 

          if ($dist[$i] > $dist[$j] + $graph[$j][$i]) { 

           echo 'The graph contains a negative-weight cycle!'; 

           return []; 

          } 

      } 

        } 

    return $dist; 

} 

```

与 Dijkstra 算法不同的是，我们不是在跟踪前任。我们在松弛过程中考虑距离。由于我们在 PHP 中使用整数的最大值，它自动取消了选择值为 0 的不存在边作为最小路径的可能性。实现的最后部分检测给定图中的任何负循环，并在这种情况下返回一个空数组：

```php
$source = 0; 

$distances = bellmanFord($graph, $source); 

foreach($distances as $target => $distance) { 

    echo "distance from $source to $target is $distance \n"; 

} 

```

这将产生以下输出，显示了从我们的源节点到其他节点的最短路径距离：

```php
distance from 0 to 0 is 0

distance from 0 to 1 is 3

distance from 0 to 2 is 5

distance from 0 to 3 is 7

distance from 0 to 4 is 9

distance from 0 to 5 is 8

```

Bellman-Ford 算法的运行时间复杂度为**O**(*V*, *E*)。

# 理解最小生成树（MST）

假设我们正在设计一个新的办公园区，其中有多栋建筑相互连接。如果我们考虑每栋建筑之间的互联性，将需要大量的电缆。然而，如果我们能够通过一种共同的连接方式将所有建筑物连接起来，其中每栋建筑物只与其他建筑物通过一个连接相连，那么这个解决方案将减少冗余和成本。如果我们把我们的建筑看作顶点，建筑之间的连接看作边，我们可以使用这种方法构建一个图。我们试图解决的问题也被称为**最小生成树**或**MST**。考虑以下图。我们有 10 个顶点和 21 条边。然而，我们可以用只有九条边（黑线）连接所有 10 个顶点。这将使我们的成本或距离保持在最低水平：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00087.jpg)

有几种算法可以用来从给定的图中找到最小生成树。最流行的两种是 Prim 算法和 Kruskal 算法。我们将在接下来的部分探讨这两种算法。

# 实现 Prim 生成树算法

Prim 算法用于寻找最小生成树依赖于贪婪方法。贪婪方法被定义为一种算法范例，其中我们尝试通过考虑每个阶段的局部最优解来找到全局最优解。我们将在第十一章中探讨贪婪算法，*使用高级技术解决问题*。在贪婪方法中，算法创建边的子集，并找出子集中成本最低的边。这个边的子集将包括所有顶点。它从任意位置开始，并通过选择顶点之间最便宜的可能连接来逐个顶点地扩展树。让我们考虑以下图：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00088.jpg)

现在，我们将应用 Prim 算法的一个非常基本的版本，以获得最小生成树以及边的最小成本或权重。图将看起来像这样，作为邻接矩阵：

```php
$G = [ 

    [0, 3, 1, 6, 0, 0], 

    [3, 0, 5, 0, 3, 0], 

    [1, 5, 0, 5, 6, 4], 

    [6, 0, 5, 0, 0, 2], 

    [0, 3, 6, 0, 0, 6], 

    [0, 0, 4, 2, 6, 0] 

]; 

```

现在，我们将实现 Prim 最小生成树的算法。我们假设我们将从顶点 0 开始找出整个生成树，因此我们只需将图的邻接矩阵传递给函数，它将显示生成树的连接边以及最小成本：

```php
function primMST(array $graph) { 

    $parent = [];   // Array to store the MST 

    $key = [];     // used to pick minimum weight edge         

    $visited = [];   // set of vertices not yet included in MST 

    $len = count($graph); 

    // Initialize all keys as MAX 

    for ($i = 0; $i < $len; $i++) { 

      $key[$i] = PHP_INT_MAX; 

      $visited[$i] = false; 

    } 

    $key[0] = 0; 

    $parent[0] = -1; 

    // The MST will have V vertices 

    for ($count = 0; $count < $len - 1; $count++) { 

  // Pick the minimum key vertex 

  $minValue = PHP_INT_MAX; 

  $minIndex = -1; 

  foreach (array_keys($graph) as $v) { 

      if ($visited[$v] == false && $key[$v] < $minValue) { 

        $minValue = $key[$v]; 

        $minIndex = $v; 

      } 

  } 

  $u = $minIndex; 

  // Add the picked vertex to the MST Set 

  $visited[$u] = true; 

  for ($v = 0; $v < $len; $v++) { 

      if ($graph[$u][$v] != 0 && $visited[$v] == false && 

        $graph[$u][$v] < $key[$v]) { 

          $parent[$v] = $u; 

          $key[$v] = $graph[$u][$v]; 

      } 

  } 

    } 

    // Print MST 

    echo "Edge\tWeight\n"; 

    $minimumCost = 0; 

    for ($i = 1; $i < $len; $i++) { 

      echo $parent[$i] . " - " . $i . "\t" . $graph[$i][$parent[$i]] 

         "\n"; 

      $minimumCost += $graph[$i][$parent[$i]]; 

    } 

    echo "Minimum cost: $minimumCost \n"; 

} 

```

现在，如果我们用我们的图$G$调用函数`primMST`，则以下将是算法构建的输出和最小生成树：

```php
Edge    Weight

0 - 1   3

0 - 2   1

5 - 3   2

1 - 4   3

2 - 5   4

Minimum cost: 13

```

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00089.jpg)

还有其他实现 Prim 算法的方法，如使用斐波那契堆、优先队列等。这与 Dijkstra 算法寻找最短路径非常相似。我们的实现具有**O**(*V²*)的时间复杂度。使用二叉堆和斐波那契堆，我们可以显著降低复杂度。

# Kruskal 算法的生成树

另一个用于寻找最小生成树的流行算法是 Kruskal 算法。它类似于 Prim 算法，并使用贪婪方法来找到解决方案。以下是我们需要实现 Kruskal 算法的步骤：

1.  创建一个森林**T**（一组树），图中的每个顶点都是一个单独的树。

1.  创建一个包含图中所有边的集合**S**。

1.  当**S**非空且**T**尚未跨越时：

1\. 从**S**中移除权重最小的边。

2\. 如果该边连接两棵不同的树，则将其添加到森林中，将两棵树合并成一棵树；否则，丢弃该边。

我们将使用与 Prim 算法相同的图。以下是 Kruskal 算法的实现：

```php
function Kruskal(array $graph): array { 

    $len = count($graph); 

    $tree = []; 

    $set = []; 

    foreach ($graph as $k => $adj) { 

    $set[$k] = [$k]; 

    } 

    $edges = []; 

    for ($i = 0; $i < $len; $i++) { 

      for ($j = 0; $j < $i; $j++) { 

        if ($graph[$i][$j]) { 

          $edges[$i . ',' . $j] = $graph[$i][$j]; 

        } 

    } 

    } 

    asort($edges); 

    foreach ($edges as $k => $w) { 

    list($i, $j) = explode(',', $k); 

    $iSet = findSet($set, $i); 

    $jSet = findSet($set, $j); 

    if ($iSet != $jSet) { 

        $tree[] = ["from" => $i, "to" => $j, 

    "cost" => $graph[$i][$j]]; 

        unionSet($set, $iSet, $jSet); 

    } 

    } 

    return $tree; 

} 

function findSet(array &$set, int $index) { 

    foreach ($set as $k => $v) { 

      if (in_array($index, $v)) { 

        return $k; 

      } 

    } 

    return false; 

} 

function unionSet(array &$set, int $i, int $j) { 

    $a = $set[$i]; 

    $b = $set[$j]; 

    unset($set[$i], $set[$j]); 

    $set[] = array_merge($a, $b); 

} 

```

正如我们所看到的，我们有两个单独的函数——`unionSet`和`findSet`——来执行两个不相交集合的并操作，以及找出一个数字是否存在于集合中。现在，让我们用我们构建的图运行程序：

```php
$graph = [ 

    [0, 3, 1, 6, 0, 0], 

    [3, 0, 5, 0, 3, 0], 

    [1, 5, 0, 5, 6, 4], 

    [6, 0, 5, 0, 0, 2], 

    [0, 3, 6, 0, 0, 6], 

    [0, 0, 4, 2, 6, 0] 

]; 

$mst = Kruskal($graph); 

$minimumCost = 0; 

foreach($mst as $v) { 

    echo "From {$v['from']} to {$v['to']} cost is {$v['cost']} \n"; 

    $minimumCost += $v['cost']; 

} 

echo "Minimum cost: $minimumCost \n"; 

```

这将产生以下输出，与我们从 Prim 算法得到的输出类似：

```php
From 2 to 0 cost is 1

From 5 to 3 cost is 2

From 1 to 0 cost is 3

From 4 to 1 cost is 3

From 5 to 2 cost is 4

Minimum cost: 13

```

Kruskal 算法的复杂度是**O**(*E log V*），这比通用的 Prim 算法实现更好。

# 总结

在本章中，我们讨论了不同的图算法及其操作。图在解决各种问题时非常方便。我们已经看到，对于相同的图，我们可以应用不同的算法并获得不同的性能。我们必须仔细选择要应用的算法，这取决于问题的性质。由于某些限制，本书中我们略过了许多其他图的主题。有一些主题，如图着色、二分匹配和流问题，应该在适用的地方进行研究和应用。在下一章中，我们将把重点转移到本书的最后一个数据结构主题，称为堆，学习堆数据结构的不同用法。


# 第十章：理解和使用堆

堆是一种基于树抽象数据类型的专门数据结构，用于许多算法和数据结构。可以使用堆构建的常见数据结构是优先队列。而基于堆数据结构的最流行和高效的排序算法之一是堆排序。在本章中，我们将讨论堆的属性、不同的堆变体和堆操作。随着我们在本章的进展，我们还将使用 SPL 实现堆。我们现在将在下一节探讨堆及其定义。

# 什么是堆？

根据定义，堆是一种支持堆属性的专门树数据结构。堆属性被定义为堆结构的根节点要么比其子节点小，要么比其子节点大。如果父节点大于子节点，则称为最大堆，如果父节点小于子节点，则称为最小堆。以下图显示了最大堆的示例：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00090.jpg)

如果我们看根节点，值**100**大于两个子节点**19**和**36**。同样对于**19**，该值大于**17**和**3**。对**36**和**17**也适用相同的规则。从树结构中可以看出，树并没有完全排序或有序。但重要的事实是我们总是可以在树的根部找到最大值或最小值，这对于许多用例来说非常高效。

堆结构有许多变体，如二叉堆、b-堆、斐波那契堆、三元堆、treap、弱堆等。二叉堆是堆实现中最流行的之一。二叉堆是一棵完全二叉树，其中树的所有内部级别都是完全填充的。最后一级可以完全填充或部分填充。由于我们考虑的是二叉堆，我们可以在对数时间内执行大多数操作。在本书中，我们将专注于二叉堆的实现和操作。

# 堆操作

正如我们已经多次提到的，堆是一种专门的树数据结构，我们必须确保首先从给定的项目列表构造一个堆。由于堆具有严格的堆属性，我们必须在每一步满足堆属性。以下是堆的一些核心操作：

+   创建堆

+   插入一个新值

+   从堆中提取最小值或最大值

+   删除一个值

+   交换

从给定的项目或数字列表创建堆需要我们确保满足堆属性和二叉树属性。这意味着父节点必须大于或小于子节点，并且对树中的所有节点都成立。而且树必须始终是一棵完全二叉树。在创建堆时，我们从一个节点开始，并将新节点插入堆中。

插入节点操作有一组定义的步骤。我们不能从任意节点开始。插入操作的步骤如下：

1.  在堆的底部插入新节点。

1.  检查新节点与父节点值是否按正确顺序。如果它们按正确顺序，则停在那里。

1.  如果它们不按正确顺序，交换它们并移动到上一步，检查新交换的节点与其父节点。这一步与前一步一起被称为 sift up 或 up-heap，或 bubble-up，或 heapify-up 等。

提取操作（最小或最大）从堆中取出根节点。之后，我们必须执行以下操作，以确保剩余堆的堆属性：

1.  将堆中的最后一个节点移动为新根。

1.  将新根节点与子节点进行比较，如果它们按正确顺序，则停止。

1.  如果不是，则将根节点与子节点交换（对于`MinHeap`来说是最小子节点，对于`MaxHeap`来说是最大子节点），并继续进行上一步。这一步和前一步被称为筛选或下沉，或冒泡下沉，或堆化下沉等等。

在堆中，交换是一个重要的操作。在许多情况下，我们必须交换两个节点的两个值，而不影响树的属性。现在我们将使用 PHP 7 实现二叉堆。

# 在 PHP 中实现二叉堆

实现二叉堆的最流行的方法之一是使用数组。由于堆是完全二叉树，因此可以很容易地使用数组实现。如果我们将根项目视为索引 1，则子项目将位于索引 2 和 3。我们可以将此表示为根为*i*，左子为*2*i*，右子为*2*i +1*。此外，我们将以我们的示例实现平均堆。因此，让我们从最小堆实现的类结构开始。

首先，我们将创建一个`MinHeap`类，它将具有两个属性，一个用于存储堆数组，另一个用于任何给定时刻堆中元素的数量。以下是该类的代码：

```php
class MinHeap { 

    public $heap; 

    public $count; 

    public function __construct(int $size) { 

        $this->heap = array_fill(0, $size + 1, 0); 

        $this->count = 0; 

    } 

}

```

如果我们看一下前面的代码，我们可以看到我们已经将堆数组初始化为从 0 索引到`$size + 1`的所有 0 值。由于我们考虑将根放在索引 1 处，我们将需要一个带有额外空间的数组。现在我们需要一种方法来从给定数组构建堆。由于我们必须满足堆属性，我们必须向堆中添加一个项目，并使用 C 步骤检查堆属性是否满足。以下是通过一次插入一个项目来创建堆的代码块，以及`siftUp`过程：

```php
public function create(array $arr = []) { 

    if ($arr) { 

        foreach ($arr as $val) { 

            $this->insert($val); 

        } 

    } 

} 

public function insert(int $i) { 

    if ($this->count == 0) { 

        $this->heap[1] = $i; 

        $this->count = 2; 

    } 

    else { 

        $this->heap[$this->count++] = $i; 

        $this->siftUp(); 

    } 

} 

public function siftUp() { 

    $tmpPos = $this->count - 1; 

    $tmp = intval($tmpPos / 2); 

    while ($tmpPos > 0 &&  

    $this->heap[$tmp] > $this->heap[$tmpPos]) { 

        $this->swap($tmpPos, $tmp); 

        $tmpPos = intval($tmpPos / 2); 

        $tmp = intval($tmpPos / 2); 

    } 

} 

```

首先，我们使用`create`方法从数组构建堆。对于数组中的每个元素，我们使用`insert`方法将其插入堆中。在`insert`方法中，我们检查堆的当前大小是否为 0。如果当前大小为 0，则将第一个项目添加到索引 1，并将下一个计数器设置为 2。如果堆已经有一个项目，我们将新项目存储在最后一个位置并增加计数器。我们还调用`siftUp()`方法来确保新插入的值满足堆属性。

在`siftUp`方法中，我们考虑最后一个位置及其父位置进行比较。如果子值小于父值，我们交换它们。我们继续这样做，直到达到顶部的根节点。这个方法确保了如果插入的值在最后是最小的，它将被筛选到树中。但如果不是，树将保持不变。虽然我们已经谈到了交换，但我们还没有看到实现。这里是实现：

```php
public function swap(int $a, int $b) { 

    $tmp = $this->heap[$a]; 

    $this->heap[$a] = $this->heap[$b]; 

    $this->heap[$b] = $tmp; 

}

```

由于根元素在堆中具有最小值（我们正在实现最小堆）。`extract`方法将始终返回当前堆的最小值：

```php
    public function extractMin() { 

        $min = $this->heap[1]; 

        $this->heap[1] = $this->heap[$this->count - 1]; 

        $this->heap[--$this->count] = 0; 

        $this->siftDown(1); 

        return $min; 

    }

```

`extractMin`方法返回数组的第一个索引，并用数组的最后一个项目替换它。之后，它对新放置的根进行`siftDown`检查，以确保堆属性。由于我们正在提取根值，我们将最后一个索引值替换为 0，这是我们用于初始化堆数组的值。现在我们将编写`extract`方法，我们称之为`siftDown`方法：

```php
public function siftDown(int $k) { 

    $smallest = $k; 

    $left = 2 * $k; 

    $right = 2 * $k + 1; 

    if ($left < $this->count &&  

    $this->heap[$smallest] > $this->heap[$left]) { 

        $smallest = $left; 

    } 

    if ($right < $this->count && $this->heap[$smallest] > $this-  

      >heap[$right]) { 

        $smallest = $right; 

    }

    if ($smallest != $k) {

        $this->swap($k, $smallest); 

        $this->siftDown($smallest); 

    }

} 

```

我们认为索引`$k`处的项目是最小值。然后我们将最小值与左右子节点进行比较。如果有更小的值可用，我们将最小值与根节点交换，直到树满足堆属性。这个函数每次需要交换时都会递归调用自己。现在我们需要另一个方法来将当前堆显示为字符串。为此，我们可以编写一个小方法如下：

```php
public function display() { 

    echo implode("\t", array_slice($this->heap, 1)) . "\n"; 

}

```

现在，如果我们把所有的部分放在一起，我们就有了一个坚实的最小堆实现。让我们现在运行一个测试，看看我们的实现是否满足最小堆的属性。这是我们可以运行的代码，来构建堆并多次从堆中提取最小值：

```php
$numbers = [37, 44, 34, 65, 26, 86, 129, 83, 9]; 

echo "Initial array \n" . implode("\t", $numbers) . "\n"; 

$heap = new MinHeap(count($numbers)); 

$heap->create($numbers); 

echo "Constructed Heap\n"; 

$heap->display(); 

echo "Min Extract: " . $heap->extractMin() . "\n"; 

$heap->display(); 

echo "Min Extract: " . $heap->extractMin() . "\n"; 

$heap->display(); 

echo "Min Extract: " . $heap->extractMin() . "\n"; 

$heap->display(); 

echo "Min Extract: " . $heap->extractMin() . "\n"; 

$heap->display(); 

echo "Min Extract: " . $heap->extractMin() . "\n"; 

$heap->display(); 

echo "Min Extract: " . $heap->extractMin() . "\n"; 

$heap->display(); 

```

如果我们运行这段代码，以下输出将显示在终端中：

```php
Initial array

37      44      34      65      26      86      129     83      9

Constructed Heap

9       26      37      34      44      86      129     83      65

Min Extract: 9

26      34      37      65      44      86      129     83      0

Min Extract: 26

34      44      37      65      83      86      129     0       0

Min Extract: 34

37      44      86      65      83      129     0       0       0

Min Extract: 37

44      65      86      129     83      0       0       0       0

Min Extract: 44

65      83      86      129     0       0       0       0       0

Min Extract: 65

83      129     86      0       0       0       0       0       0

```

从前面的输出中可以看到，当我们构建最小堆时，值为`9`的最小值在根中。然后我们提取了最小值，我们从堆中取出了`9`。然后根被下一个最小值`26`取代，然后是`34`，`37`，`44`和`65`。每次我们取出最小值时，堆都会重新构建以获取最小值。由于我们已经看到了堆数据结构的所有适用操作，现在我们将分析不同堆操作的复杂度。

# 分析堆操作的复杂度

由于堆实现有不同的变体，复杂度在不同的实现中也会有所不同。堆的一个关键事实是提取操作总是需要`O(1)`的时间来从堆中获取最大或最小值。由于我们专注于二叉堆实现，我们将看到二叉堆操作的分析：

| **操作** | **复杂度 - 平均** | **复杂度 - 最坏** |
| --- | --- | --- |
| 搜索 | `O(n)` | `O(n)` |
| 插入 | `O(1)` | `O(log n)` |
| 删除 | `O(log n)` | `O(log n)` |
| 提取 | `O(1)` | `O(1)` |
| 空间 | `O(n)` | `O(n)` |

由于堆不是完全排序的，搜索操作将比常规二叉搜索树需要更多时间。

# 使用堆作为优先队列

使用堆数据结构的主要方式之一是创建优先队列。正如我们在第四章中所见，*构建栈和队列*，优先队列是特殊的队列，其中 FIFO 行为取决于元素的优先级，而不是元素添加到队列的方式。我们已经看到了使用链表和 SPL 的实现。现在我们将探索使用堆和特别是最大堆实现优先队列。

现在我们将使用`MaxHeap`来实现优先队列。在这里，最大优先级的项目首先从队列中移除。我们的实现将类似于我们上次实现的`MinHeap`，只是有一点不同。我们希望从 0 开始而不是从 1 开始。因此，左右子节点的计算也会发生变化。这将帮助我们理解使用数组构建堆的两种方法。这是`MaxHeap`类的实现：

```php
class MaxHeap { 

    public $heap; 

    public $count; 

    public function __construct(int $size) { 

        $this->heap = array_fill(0, $size, 0); 

        $this->count = 0; 

    } 

    public function create(array $arr = []) { 

        if ($arr) { 

            foreach ($arr as $val) { 

                $this->insert($val); 

            } 

        } 

    } 

    public function display() { 

        echo implode("\t", array_slice($this->heap, 0)) . "\n"; 

    } 

    public function insert(int $i) { 

    if ($this->count == 0) { 

        $this->heap[0] = $i; 

        $this->count = 1; 

    } else { 

        $this->heap[$this->count++] = $i; 

        $this->siftUp(); 

    } 

    } 

public function siftUp() { 

    $tmpPos = $this->count - 1; 

    $tmp = intval($tmpPos / 2); 

    while ($tmpPos > 0 && $this->heap[$tmp] < $this->heap[$tmpPos]) { 

        $this->swap($tmpPos, $tmp); 

        $tmpPos = intval($tmpPos / 2); 

        $tmp = intval($tmpPos / 2); 

    } 

} 

public function extractMax() { 

    $min = $this->heap[0]; 

    $this->heap[0] = $this->heap[$this->count - 1]; 

    $this->heap[$this->count - 1] = 0; 

    $this->count--; 

    $this->siftDown(0); 

    return $min; 

} 

public function siftDown(int $k) { 

    $largest= $k; 

    $left = 2 * $k + 1; 

    $right = 2 * $k + 2; 

    if ($left < $this->count  

      && $this->heap[$largest] < $this->heap[$left]) { 

        $largest = $left; 

    } 

    if ($right < $this->count  

      && $this->heap[$largest] < $this->heap[$right]) { 

        $largest = $right; 

    } 

    if ($largest!= $k) { 

        $this->swap($k, $largest); 

        $this->siftDown($largest); 

    } 

} 

    public function swap(int $a, int $b) { 

      $temp = $this->heap[$a]; 

      $this->heap[$a] = $this->heap[$b]; 

      $this->heap[$b] = $temp; 

    }

}

```

让我们来看看`MaxHeap`类的实现。我们的`MaxHeap`实现与上一节的`MinHeap`实现有一些细微的差异。第一个区别是，对于`MaxHeap`，我们有一个大小为*n*的数组，而对于`MinHeap`，我们有一个大小为*n+1*的数组。这使得我们对`MaxHeap`的插入操作从索引 0 开始插入，而在`MinHeap`中，我们从索引 1 开始。`siftUp`功能只有在新插入项的值大于即时父值时才将值移至顶部。此外，`extractMax`方法返回数组中索引 0 的第一个值，即堆中的最大值。一旦我们提取了最大值，我们需要从剩余项中获取最大值并将其存储在索引 0 处。`siftDown`函数还用于检查左侧或右侧子值是否大于父节点值，并交换值以将最大值存储在父节点处。我们继续递归地执行此操作，以确保在函数调用结束时将最大值存储在根中。如果需要，可以将此`MaxHeap`实现用作独立的堆实现。由于我们计划使用堆来实现优先级队列，因此我们将添加另一个类来扩展`MaxHeap`类，以展示优先级队列的特性。让我们探索以下代码：

```php
class PriorityQ extends MaxHeap { 

    public function __construct(int $size) {  

        parent::__construct($size); 

    } 

    public function enqueue(int $val) { 

        parent::insert($val); 

    } 

    public function dequeue() { 

        return parent::extractMax(); 

    }

}

```

在这里，我们只是扩展了`MaxHeap`类，并添加了一个包装器，使用`insert`和`extractMax`进行`enqueue`和`dequeue`操作。现在让我们用与`MinHeap`相同的数字运行`PriorityQ`代码：

```php
$numbers = [37, 44, 34, 65, 26, 86, 129, 83, 9]; 

$pq = new PriorityQ(count($numbers)); 

foreach ($numbers as $number) { 

    $pq->enqueue($number); 

} 

echo "Constructed Heap\n"; 

$pq->display(); 

echo "DeQueued: " . $pq->dequeue() . "\n"; 

$pq->display(); 

echo "DeQueued: " . $pq->dequeue() . "\n"; 

$pq->display(); 

echo "DeQueued: " . $pq->dequeue() . "\n"; 

$pq->display(); 

echo "DeQueued: " . $pq->dequeue() . "\n"; 

$pq->display(); 

echo "DeQueued: " . $pq->dequeue() . "\n"; 

$pq->display(); 

echo "DeQueued: " . $pq->dequeue() . "\n"; 

$pq->display();

```

从前面的代码中可以看出，我们并不是直接从数组构建堆。我们使用优先级队列类将每个数字入队。此外，出队操作将从队列中获取优先级最高的项。如果从命令行运行此代码，将会得到以下输出：

```php
Constructed Heap

129     86      44      83      26      34      37      65      9

DeQueued: 129

86      83      44      65      26      34      37      9       0

DeQueued: 86

83      65      44      9       26      34      37      0       0

DeQueued: 83

65      37      44      9       26      34      0       0       0

DeQueued: 65

44      37      34      9       26      0       0       0       0

DeQueued: 44

37      26      34      9       0       0       0       0       0

DeQueued: 37

34      26      9       0       0       0       0       0       0

```

从输出中可以看出，`MaxHeap`实现帮助我们在每次出队操作时获取最大值项。这是实现优先级队列的一种方式。如果需要，我们还可以一次对整个堆进行排序，然后使用排序后的数组作为优先级队列。为此，我们可以实现一个称为堆排序的排序函数。这是计算机编程中最有效和最常用的排序机制之一。现在我们将在下一节中探索这一点。

# 使用堆排序

堆排序要求我们从给定的元素列表构建堆，然后不断检查堆属性，以使整个堆始终保持排序。与常规堆不同，常规堆在新插入值满足条件后停止检查堆属性，而在堆排序实现过程中，我们继续对下一个元素进行这样的操作。堆排序的伪代码如下：

```php
Heapsort(A as array) 

    BuildHeap(A) 

    for i = n-1 to 0 

        swap(A[0], A[i]) 

        n = n - 1 

        Heapify(A, 0) 

BuildHeap(A as array) 

    n = elements_in(A) 

    for i = floor(n/2) to 0 

        Heapify(A,i) 

Heapify(A as array, i as int) 

    left = 2i+1 

    right = 2i+2 

    max = i 

    if (left <= n) and (A[left] > A[i]) 

        max = left 

    if (right<=n) and (A[right] > A[max]) 

        max = right 

    if (max != i) 

        swap(A[i], A[max]) 

        Heapify(A, max) 

```

伪代码表明，每当我们尝试对一系列元素进行排序时，起始过程取决于构建堆。每次向堆中添加一个项时，我们都会通过`heapify`函数检查是否满足堆属性。构建好堆后，我们会检查所有元素的堆属性。现在让我们根据前面的伪代码实现堆排序：

```php
function heapSort(array &$a) { 

    $length = count($a); 

    buildHeap($a); 

    $heapSize = $length - 1; 

    for ($i = $heapSize; $i >= 0; $i--) { 

      $tmp = $a[0]; 

      $a[0] = $a[$heapSize]; 

      $a[$heapSize] = $tmp; 

      $heapSize--; 

      heapify($a, 0, $heapSize); 

    } 

} 

function buildHeap(array &$a) { 

    $length = count($a); 

    $heapSize = $length - 1; 

    for ($i = ($length / 2); $i >= 0; $i--) { 

        heapify($a, $i, $heapSize); 

    } 

} 

function heapify(array &$a, int $i, int $heapSize) { 

    $largest = $i; 

    $l = 2 * $i + 1; 

    $r = 2 * $i + 2; 

    if ($l <= $heapSize && $a[$l] > $a[$i]) { 

        $largest = $l; 

    } 

    if ($r <= $heapSize && $a[$r] > $a[$largest]) { 

        $largest = $r; 

    } 

    if ($largest != $i) { 

      $tmp = $a[$i]; 

      $a[$i] = $a[$largest]; 

      $a[$largest] = $tmp; 

      heapify($a, $largest, $heapSize); 

    } 

} 

```

现在让我们使用`heapSort`函数对数组进行排序。由于我们传递的参数是按引用传递的，因此我们不会从函数中返回任何内容。实际数组将在操作结束时排序：

```php
$numbers = [37, 44, 34, 65, 26, 86, 143, 129, 9]; 

heapSort($numbers); 

echo implode("\t", $numbers); 

```

如果运行此代码，将在命令行中输出以下内容：

```php
9       26      34      37      44      65      86      129     143

```

如果我们想要将排序改为降序，我们只需要在`heapify`函数中改变比较。如果我们考虑`heapSort`算法的时间和空间复杂度，我们会发现堆排序是排序算法中最好的复杂度：

| 最佳时间复杂度 | `Ω(nlog(n))` |
| --- | --- |
| 最坏时间复杂度 | `O(nlog(n))` |
| 平均时间复杂度 | `Θ(nlog(n))` |
| 空间复杂度（最坏情况） | `O(1)` |

与归并排序相比，堆排序具有更好的空间复杂度。因此，许多开发人员更喜欢使用堆排序来对项目列表进行排序。

# 使用 SplHeap、SplMaxHeap 和 SplMinHeap

如果我们不想实现自己的堆实现，我们可以使用标准 PHP 库（SPL）中的内置堆类。SPL 有三种不同的堆实现。一种是用于通用堆的`SplHeap`，一种是用于`MaxHeap`的`SplMaxHeap`，还有一种是用于`MinHeap`的`SplMinHeap`。重要的是要知道，SPL 类在 PHP 7 上运行时并不被认为是非常高效的。因此，我们不会在这里详细探讨它们。我们只会专注于一个示例，以便如果我们使用的是 PHP 7 之外的其他版本，我们可以使用这些内置类。让我们尝试使用`SplMaxHeap`的一个示例：

```php
$numbers = [37, 44, 34, 65, 26, 86, 143, 129, 9]; 

$heap = new SplMaxHeap; 

foreach ($numbers as $number) { 

    $heap->insert($number); 

} 

while (!$heap->isEmpty()) { 

    echo $heap->extract() . "\t"; 

}

```

由于我们使用了最大堆，我们期望输出是按降序排列的。以下是从命令行输出的结果：

```php
143     129     86      65      44      37      34      26      9

```

如果我们想以另一种方式进行排序，我们可以使用`SplMinHeap`。

# 摘要

在本章中，我们学习了另一种高效的数据结构，名为堆。当我们使用堆来实现优先队列时，它们被认为是最大效率的实现。我们还学习了另一种高效的排序方法，名为堆排序，可以通过堆数据结构实现。在这里，我们将总结本书关于数据结构的讨论。在剩下的章节中，我们将专注于高级算法，算法的内置函数和数据结构，以及最后的函数式数据结构。首先，我们将在下一章中探索动态规划的世界。


# 第十一章：使用高级技术解决问题

到目前为止，我们在本书中已经探讨了不同的数据结构和算法。我们还没有探索一些最激动人心的算法领域。在计算机编程中有许多高效的方法。在本章中，我们将重点关注一些关键的高级技术和概念。这些主题非常重要，以至于可以单独写一本书来讨论它们。然而，我们将专注于对这些高级主题的基本理解。当我们说高级主题时，我们指的是记忆化、动态规划、贪婪算法、回溯、解谜、机器学习等。让我们在接下来的章节中学习一些新颖和激动人心的主题。

# 记忆化

记忆化是一种优化技术，我们在其中存储先前昂贵操作的结果，并在不重复操作的情况下使用它们。这有助于显著加快解决方案的速度。当我们遇到可以重复子问题的问题时，我们可以轻松地应用这种技术来存储这些结果，并在以后使用它们而不重复步骤。由于 PHP 对关联数组和动态数组属性有很好的支持，我们可以毫无问题地缓存结果。我们必须记住的一件事是，尽管我们通过缓存结果来节省时间，但我们需要更多的内存来存储这些结果。因此，我们必须在空间和内存之间进行权衡。现在，让我们重新访问第五章，*应用递归算法-递归*，以了解我们生成斐波那契数的递归示例。我们将只需修改该函数，添加一个计数器来知道函数被调用的次数以及函数运行时间来获取第 30 个斐波那契数。以下是此代码：

```php
$start Time = microtime(); 

$count = 0;

function fibonacci(int $n): int { 

    global $count; 

    $count++; 

    if ($n == 0) { 

        return 1; 

    } else if ($n == 1) { 

        return 1; 

    } else { 

        return fibonacci($n - 1) + fibonacci($n - 2); 

    } 

} 

echo fibonacci(30) . "\n"; 

echo "Function called: " . $count . "\n"; 

$endTime = microtime(); 

echo "time =" . ($endTime - $startTime) . "\n";

```

这将在命令行中产生以下输出。请注意，计时和结果可能会因系统不同或 PHP 版本不同而有所不同。这完全取决于程序运行的位置：

```php
1346269

Function called: 2692537

time =0.531349

```

第一个数字 1346269 是第 30 个斐波那契数，下一行显示在生成第 30 个数字时`fibonacci`函数被调用了 2692537 次。整个过程花了 0.5 秒（我们使用了 PHP 的`microtime`函数）。如果我们要生成第 50 个斐波那契数，函数调用次数将超过 400 亿次。这是一个非常大的数字。然而，我们知道根据斐波那契数列的公式，当我们计算 n 时，我们是通过 n-1 和 n-2 来计算的；这些在之前的步骤中已经计算过了。所以，我们在重复这些步骤，因此，这会浪费我们的时间和效率。现在，让我们将斐波那契结果存储在一个索引数组中，并检查我们要找的斐波那契数是否已经计算过。如果已经计算过，我们将使用它；否则，我们将计算并存储结果。以下是使用相同递归过程生成斐波那契数的修改后的代码，但是借助记忆化：

```php
$startTime = microtime(); 

$fibCache = []; 

$count = 0; 

function fibonacciMemoized(int $n): int { 

    global $fibCache; 

    global $count; 

    $count++; 

    if ($n == 0 || $n == 1) { 

        return 1; 

    } else {

    if (isset($fibCache[$n - 1])) { 

        $tmp = $fibCache[$n - 1]; 

    } else {

        $tmp = fibonacciMemoized($n - 1); 

        $fibCache[$n - 1] = $tmp; 

    } 

    if (isset($fibCache[$n - 2])) { 

        $tmp1 = $fibCache[$n - 2]; 

    } else { 

        $tmp1 = fibonacciMemoized($n - 2); 

        $fibCache[$n - 2] = $tmp1; 

    } 

    return $tmp + $tmp1; 

    } 

} 

echo fibonacciMemoized(30) . "\n"; 

echo "Function called: " . $count . "\n"; 

$endTime = microtime(); 

echo "time =" . ($endTime - $startTime) . "\n"; 

```

如前面的代码所示，我们引入了一个名为`$fibCache`的新全局变量，它将存储计算出的斐波那契数。我们还检查我们要查找的数字是否已经在数组中。如果数字已经存储在我们的缓存数组中，我们就不再计算斐波那契数。如果现在运行这段代码，我们将看到以下输出：

```php
1346269

Function called: 31

time =5.299999999997E-5

```

现在，让我们检查结果。第 30 个斐波那契数与上次相同。但是，看一下函数调用次数。只有 31 次，而不是 270 万次。现在，让我们看看时间。我们只用了 0.00005299 秒，比非记忆化版本快了 10000 倍。

通过一个简单的例子，我们可以看到我们可以通过利用适用的记忆化来优化我们的解决方案。我们必须记住的一件事是，记忆化将在我们有重复的子问题或者我们必须考虑以前的计算来计算当前或未来的计算的情况下更有效。尽管记忆化将占用额外的空间来存储部分计算的数据，但利用记忆化可以大幅提高性能

# 模式匹配算法

模式匹配是我们日常工作中执行的最常见任务之一。PHP 内置支持正则表达式，大多数情况下，我们依赖正则表达式和内置字符串函数来解决这类问题的常规需求。PHP 有一个名为`strops`的现成函数，它返回文本中字符串的第一次出现的位置。由于它只返回第一次出现的位置，我们可以尝试编写一个函数，它将返回所有可能的位置。我们首先将探讨蛮力方法，其中我们将检查实际字符串的每个字符与模式字符串的每个字符。以下是将为我们完成工作的函数：

```php
function strFindAll(string $pattern, string $txt): array { 

    $M = strlen($pattern); 

    $N = strlen($txt); 

    $positions = []; 

    for ($i = 0; $i <= $N - $M; $i++) { 

      for ($j = 0; $j < $M; $j++) 

          if ($txt[$i + $j] != $pattern[$j]) 

          break; 

      if ($j == $M) 

          $positions[] = $i; 

  }

    return $positions; 

} 

```

这种方法非常直接。我们从实际字符串的位置 0 开始，一直进行到`$N-$M`位置，其中`$M`是我们要查找的模式的长度。即使在最坏的情况下，模式没有匹配，我们也不需要搜索整个字符串。现在，让我们用一些参数调用函数：

```php
$txt = "AABAACAADAABABBBAABAA"; 

$pattern = "AABA"; 

$matches = strFindAll($pattern, $txt); 

if ($matches) { 

    foreach ($matches as $pos) { 

        echo "Pattern found at index : " . $pos . "\n"; 

    } 

} 

```

这将产生以下输出：

```php
Pattern found at index : 0

Pattern found at index : 9

Pattern found at index : 16

```

如果我们查看我们的`$txt`字符串，我们可以发现我们的模式`AABA`出现了三次。第一次是在开头，第二次是在中间，第三次是在字符串末尾附近。我们编写的算法将具有`O((N - M) * M)`的复杂度，其中 N 是文本的长度，M 是我们正在搜索的模式的长度。如果需要，我们可以使用一种称为**Knuth-Morris-Pratt**（**KMP**）字符串匹配算法的流行算法来提高这种匹配的效率。

# 实现 Knuth-Morris-Pratt 算法

Knuth-Morris-Pratt（KMP）字符串匹配算法与我们刚刚实现的朴素算法非常相似。基本区别在于 KMP 算法使用部分匹配的信息，并决定在任何不匹配时停止匹配。它还可以预先计算模式可能存在的位置，以便我们可以减少重复比较或错误检查的次数。KMP 算法预先计算了一个在搜索操作期间有助于提高效率的表。在实现 KMP 算法时，我们需要计算**最长适当前缀后缀**（**LPS**）。让我们检查生成 LPS 部分的函数：

```php
function ComputeLPS(string $pattern, array &$lps) { 

    $len = 0; 

    $i = 1; 

    $M = strlen($pattern); 

    $lps[0] = 0; 

    while ($i < $M) { 

    if ($pattern[$i] == $pattern[$len]) { 

        $len++; 

        $lps[$i] = $len; 

        $i++; 

    } else { 

        if ($len != 0) { 

          $len = $lps[$len - 1]; 

        } else { 

          $lps[$i] = 0; 

          $i++; 

        } 

    } 

    } 

}

```

对于我们之前例子中的模式 AABA，LPS 将是`[0,1,0,1]`；现在，让我们为我们的字符串/模式搜索问题编写 KMP 实现：

```php
function KMPStringMatching(string $str, string $pattern): array { 

    $matches = []; 

    $M = strlen($pattern); 

    $N = strlen($str); 

    $i = $j = 0; 

    $lps = []; 

    ComputeLPS($pattern, $lps); 

    while ($i < $N) { 

    if ($pattern[$j] == $str[$i]) { 

        $j++; 

        $i++; 

    } 

    if ($j == $M) { 

        array_push($matches, $i - $j); 

        $j = $lps[$j - 1]; 

    } else if ($i < $N && $pattern[$j] != $str[$i]) { 

        if ($j != 0) 

        $j = $lps[$j - 1]; 

        else 

        $i = $i + 1; 

    } 

    } 

    return $matches; 

} 

```

上述代码是 KMP 算法的实现。现在，让我们用我们实现的算法运行以下示例：

```php
$txt = "AABAACAADAABABBBAABAA"; 

$pattern = "AABA"; 

$matches = KMPStringMatching($txt, $pattern); 

if ($matches) { 

    foreach ($matches as $pos) { 

        echo "Pattern found at index : " . $pos . "\n"; 

    }

}

```

这将产生以下输出：

```php
Pattern found at index : 0

Pattern found at index : 9

Pattern found at index : 16

```

KMP 算法的复杂度是`O(N + M)`，比常规模式匹配要好得多。这里，`O(M)`是用于计算 LPS，`O(N)`是用于 KMP 算法本身。

可以在网上找到许多关于 KMP 算法的详细描述。

# 贪婪算法

尽管名为贪婪算法，但实际上它是一种专注于在给定时刻找到最佳解决方案的编程技术。这意味着贪婪算法在希望它将导致全局最优解的情况下做出局部最优选择。我们必须记住的一件事是，并非所有贪婪方法都会带我们到全局最优解。然而，贪婪算法仍然应用于许多问题解决领域。贪婪算法最常见的用途之一是哈夫曼编码，它用于对大文本进行编码并通过将其转换为不同的代码来压缩字符串。我们将在下一节中探讨哈夫曼编码的概念和实现。

# 实现哈夫曼编码算法

**哈夫曼编码**是一种压缩技术，用于减少发送或存储消息或字符串所需的位数。它基于这样一个想法，即频繁出现的字符将具有较短的位表示，而不太频繁的字符将具有较长的位表示。如果我们将哈夫曼编码视为树结构，则较不频繁的字符或项目将位于树的顶部，而更频繁的项目将位于树的底部或叶子中。哈夫曼编码在很大程度上依赖于优先级队列。哈夫曼编码可以通过首先创建节点树来计算。

创建节点树的过程：

1.  我们必须为每个符号创建一个叶节点并将其添加到优先级队列。

1.  当队列中有多个节点时，执行以下操作：

1. 两次删除优先级最高（概率/频率最低）的节点以获得两个节点。

2. 创建一个新的内部节点，将这两个节点作为子节点，并且概率/频率等于这两个节点概率/频率的总和。

3. 将新节点添加到队列中。

1.  剩下的节点是根节点，树是完整的。

然后，我们必须从根到叶遍历构建的二叉树，在每个节点分配和累积“0”和“1”。每个叶子处累积的零和一构成了这些符号和权重的哈夫曼编码。以下是使用 SPL 优先级队列实现的哈夫曼编码算法：

```php
function huffmanEncode(array $symbols): array { 

    $heap = new SplPriorityQueue; 

    $heap->setExtractFlags(SplPriorityQueue::EXTR_BOTH); 

    foreach ($symbols as $symbol => $weight) { 

        $heap->insert(array($symbol => ''), -$weight); 

    } 

    while ($heap->count() > 1) { 

    $low = $heap->extract(); 

    $high = $heap->extract(); 

    foreach ($low['data'] as &$x) 

        $x = '0' . $x; 

    foreach ($high['data'] as &$x) 

        $x = '1' . $x; 

    $heap->insert($low['data'] + $high['data'],  

            $low['priority'] + $high['priority']); 

    } 

    $result = $heap->extract(); 

    return $result['data']; 

} 

```

在这里，我们为每个符号构建了一个最小堆，并使用它们的权重来设置优先级。一旦堆构建完成，我们依次提取两个节点，并将它们的数据和优先级组合以将它们添加回堆中。这将继续，直到只剩下一个节点，即根节点。现在，让我们运行以下代码生成哈夫曼编码：

```php
$txt = 'PHP 7 Data structures and Algorithms'; 

$symbols = array_count_values(str_split($txt)); 

$codes = huffmanEncode($symbols); 

echo "Symbol\t\tWeight\t\tHuffman Code\n"; 

foreach ($codes as $sym => $code) { 

    echo "$sym\t\t$symbols[$sym]\t\t$code\n"; 

} 

```

在这里，我们使用`str_split`将字符串分割成数组，然后使用数组计数值将其转换为一个关联数组，其中字符将是键，字符串中出现的次数将是值。上述代码将产生以下输出：

```php
Symbol          Weight          Huffman Code

i               1               00000

D               1               00001

d               1               00010

A               1               00011

t               4               001

H               1               01000

m               1               01001

P               2               0101

g               1               01100

o               1               01101

e               1               01110

n               1               01111

7               1               10000

l               1               10001

u               2               1001

 5               101

h               1               11000

c               1               11001

a               3               1101

r               3               1110

s               3               1111

```

贪婪算法有许多其他实际用途。我们将使用贪婪算法解决作业调度问题。让我们考虑一个敏捷软件开发团队的例子，他们在两周的迭代或冲刺中工作。他们有一些用户故事要完成，这些故事有一些任务的截止日期（按日期）和与故事相关的速度（故事的大小）。团队的目标是在给定的截止日期内获得冲刺的最大速度。让我们考虑以下具有截止日期和速度的任务：

| **索引** | 1 | 2 | 3 | 4 | 5 | 6 |
| --- | --- | --- | --- | --- | --- | --- |
| **故事** | S1 | S2 | S3 | S4 | S5 | S6 |
| **截止日期** | 2 | 1 | 2 | 1 | 3 | 4 |
| **速度** | 95 | 32 | 47 | 42 | 28 | 64 |

从上表中可以看出，我们有六个用户故事，它们有四个不同的截止日期，从 1 到 4。我们必须在时间槽 1 完成用户故事**S2**或**S4**，因为任务的截止日期是 1。对于故事**S1**和**S3**也是一样，它们必须在时间槽**2**之前或之内完成。然而，由于我们有**S3**，而**S3**的速度大于**S2**和**S4**，所以**S3**将被贪婪地选择为时间槽 1。让我们为我们的速度计算编写贪婪代码：

```php
function velocityMagnifier(array $jobs) { 

     $n = count($jobs); 

    usort($jobs, function($opt1, $opt2) { 

        return $opt1['velocity'] < $opt2['velocity']; 

    }); 

    $dMax = max(array_column($jobs, "deadline")); 

    $slot = array_fill(1, $dMax, -1); 

    $filledTimeSlot = 0; 

    for ($i = 0; $i < $n; $i++) { 

    $k = min($dMax, $jobs[$i]['deadline']); 

    while ($k >= 1) { 

        if ($slot[$k] == -1) { 

          $slot[$k] = $i; 

          $filledTimeSlot++; 

          break; 

        } 

        $k--; 

    } 

      if ($filledTimeSlot == $dMax) { 

          break; 

      } 

    } 

    echo("Stories to Complete: "); 

    for ($i = 1; $i <= $dMax; $i++) { 

        echo $jobs[$slot[$i]]['id']; 

        if ($i < $dMax) { 

            echo "\t"; 

        } 

    } 

    $maxVelocity = 0; 

    for ($i = 1; $i <= $dMax; $i++) { 

        $maxVelocity += $jobs[$slot[$i]]['velocity']; 

    } 

    echo "\nMax Velocity: " . $maxVelocity; 

} 

```

在这里，我们得到了作业列表（用户故事 ID，截止日期和速度），我们将用它们来找到最大速度及其相应的用户故事 ID。首先，我们使用自定义用户排序函数`usort`对作业数组进行排序，并根据它们的速度按降序对数组进行排序。之后，我们计算从截止日期列中可用的最大时间槽数。然后，我们将时间槽数组初始化为-1，以保持已使用时间槽的标志。下一个代码块是遍历每个用户故事，并为用户故事找到合适的时间槽。如果可用的时间槽已满，我们就不再继续。现在，让我们使用以下代码块运行此代码：

```php
$jobs = [ 

    ["id" => "S1", "deadline" => 2, "velocity" => 95], 

    ["id" => "S2", "deadline" => 1, "velocity" => 32], 

    ["id" => "S3", "deadline" => 2, "velocity" => 47], 

    ["id" => "S4", "deadline" => 1, "velocity" => 42], 

    ["id" => "S5", "deadline" => 3, "velocity" => 28], 

    ["id" => "S6", "deadline" => 4, "velocity" => 64] 

]; 

velocityMagnifier($jobs); 

```

这将在命令行中产生以下输出：

```php
Stories to Complete: S3    S1    S5    S6

Max Velocity: 234

```

贪婪算法可以帮助解决诸如作业调度、网络流量控制、图算法等局部优化问题。然而，要获得全局优化的解决方案，我们需要关注算法的另一个方面，即动态规划。

# 理解动态规划

动态规划是通过将复杂问题分解为较小的子问题并找到这些子问题的解决方案来解决复杂问题的一种方法。我们累积子问题的解决方案以找到全局解决方案。动态规划的好处是通过存储它们的结果来减少子问题的重新计算。动态规划是优化的一个非常著名的方法。动态规划可以解决问题，如找零钱、找到最长公共子序列、找到最长递增序列、排序 DNA 字符串等。贪婪算法和动态规划的核心区别在于，动态规划总是更倾向于全局优化的解决方案。

如果问题具有最优子结构或重叠子问题，我们可以使用动态规划来解决问题。最优子结构意味着实际问题的优化可以使用其子问题的最优解的组合来解决。换句话说，如果问题对 n 进行了优化，那么对于小于 n 或大于 n 的任何大小，它都将被优化。重叠子问题表示较小的子问题将一遍又一遍地解决，因为它们彼此重叠。斐波那契数列是重叠子问题的一个很好的例子。因此，在这里基本的递归将一点帮助也没有。动态规划只解决每个子问题一次，并且不会尝试进一步解决任何问题。这可以通过自顶向下的方法或自底向上的方法来实现。

在自顶向下的方法中，我们从一个更大的问题开始，递归地解决较小的子问题。然而，我们必须使用记忆化技术来存储子问题的结果，以便将来不必重新计算该子问题。在自底向上的方法中，我们首先解决最小的子问题，然后再转向其他较小的子问题。通常，使用多维数组以表格格式存储子问题的结果。

现在，我们将探讨动态规划世界中的一些例子。有些可能在我们日常编程问题中听起来很熟悉。我们将从著名的背包问题开始。

# 0-1 背包

背包是一种带有肩带的袋子，通常由士兵携带，以帮助他们在旅途中携带必要的物品或贵重物品。每件物品都有一个价值和确定的重量。因此，士兵必须在其最大重量限制内选择最有价值的物品，因为他们无法把所有东西都放在包里。0/1 表示我们要么可以拿走它，要么留下它。我们不能部分拿走物品。这就是著名的 0-1 背包问题。我们将采用自底向上的方法来解决 0-1 背包问题。以下是解决方案的伪代码：

```php
Procedure knapsack(n, W, w1,...,wN, v1,...,vN) 

for w = 0 to W 

    M[0, w] = 0 

for i = 1 to n 

    for w = 0 to W 

    if wi > w : 

        M[i, w] = M[i-1, w] 

    else : 

        M[i, w] = max (M[i-1, w], vi + M[i-1, w-wi ]) 

return M[n, W] 

end procedure  

```

例如，如果我们有五个物品，`[1,2,3,4,5]`，它们的重量分别为 10,20,30,40,50，最大允许的重量为 10，将使用自底向上的方法产生以下表：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00091.jpg)

正如我们所看到的，我们从底部开始构建表格，从一个物品和一个重量开始，逐渐增加到我们想要的重量，并通过选择最佳可能的物品来最大化价值计数。最后，底部右下角的最后一个单元格是 0-1 背包问题的预期结果。以下是运行该函数的实现和代码：

```php
function knapSack(int $maxWeight, array $weights, array $values, int $n) { 

    $DP = []; 

    for ($i = 0; $i <= $n; $i++) { 

      for ($w = 0; $w <= $maxWeight; $w++) { 

          if ($i == 0 || $w == 0) 

          $DP[$i][$w] = 0; 

          else if ($weights[$i - 1] <= $w) 

          $DP[$i][$w] =  

            max($values[$i-1]+$DP[$i - 1][$w - $weights[$i-1]] 

            , $DP[$i - 1][$w]); 

          else 

          $DP[$i][$w] = $DP[$i - 1][$w]; 

        } 

    } 

    return $DP[$n][$maxWeight]; 

} 

$values = [10, 20, 30, 40, 50]; 

$weights = [1, 2, 3, 4, 5]; 

$maxWeight = 10; 

$n = count($values); 

echo knapSack($maxWeight, $weights, $values, $n); 

```

这将在命令行上显示 100，这实际上与我们从前面的表中预期的结果相匹配。该算法的复杂度为 O（*n* **W*），其中 n 是物品的数量，W 是目标重量。

# 查找最长公共子序列-LCS

使用动态规划解决的另一个非常流行的算法是找到两个字符串之间的最长公共子序列或 LCS。这个过程与解决背包问题的过程非常相似，我们有一个二维表格，从一个重量开始移动到我们的目标重量。在这里，我们将从第一个字符串的第一个字符开始，并横跨整个字符串以匹配字符。我们将继续进行，直到第一个字符串的所有字符都与第二个字符串的各个字符匹配。因此，当我们找到匹配时，我们会考虑匹配单元格的左上角单元格或对角线左侧单元格。让我们考虑以下两个表格，以了解匹配是如何发生的：

|

&#124;  &#124;  &#124; A &#124; B &#124;

&#124;  &#124; 0 &#124; 0 &#124; 0 &#124;

&#124; C &#124; 0 &#124; 0 &#124; 0 &#124;

&#124; B &#124; 0 &#124; 0 &#124; 1 &#124;

|

&#124;  &#124;  &#124; B &#124; D &#124;

&#124;  &#124; 0 &#124; 0 &#124; 0 &#124;

&#124; B &#124; 0 &#124; 1 &#124; 1 &#124;

&#124; D &#124; 0 &#124; 1 &#124; 2 &#124;

|

在左侧的表中，我们有两个字符串 AB 和 CB。当 B 在表中匹配 B 时，匹配单元格的值将是其对角线单元格的值加一。这就是为什么第一个表的深色背景单元格的值为 1，因为对角线左侧单元格的值为 0。出于同样的原因，右侧表格的右下角单元格的值为 2，因为对角线单元格的值为 1。以下是查找 LCS 长度的伪代码：

```php
function LCSLength(X[1..m], Y[1..n]) 

    C = array[m][n] 

    for i := 0..m 

       C[i,0] = 0 

    for j := 0..n 

       C[0,j] = 0 

    for i := 1..m 

        for j := 1..n 

            if(i = 0 or j = 0) 

                C[i,j] := 0 

            else if X[i] = Y[j] 

                C[i,j] := C[i-1,j-1] + 1 

            else 

                C[i,j] := max(C[i,j-1], C[i-1,j]) 

    return C[m,n] 

```

以下是我们的伪代码实现，用于查找 LCS 长度：

```php
function LCS(string $X, string $Y): int { 

    $M = strlen($X); 

    $N = strlen($Y); 

    $L = []; 

    for ($i = 0; $i <= $M; $i++) 

      $L[$i][0] = 0; 

    for ($j = 0; $j <= $N; $j++) 

      $L[0][$j] = 0; 

    for ($i = 0; $i <= $M; $i++) { 

      for ($j = 0; $j <= $N; $j++) {         

          if($i == 0 || $j == 0) 

          $L[$i][$j] = 0; 

          else if ($X[$i - 1] == $Y[$j - 1]) 

          $L[$i][$j] = $L[$i - 1][$j - 1] + 1; 

          else 

          $L[$i][$j] = max($L[$i - 1][$j], $L[$i][$j - 1]); 

      } 

    } 

    return $L[$M][$N]; 

} 

```

现在，让我们运行`LCS`函数与两个字符串，看看是否可以找到最长的公共子序列：

```php
$X = "AGGTAB"; 

$Y = "GGTXAYB"; 

echo "LCS Length:".LCS( $X, $Y ); 

```

这将在命令行中产生输出`LCS Length:5`。这似乎是正确的，因为两个字符串都有 GGTAB 作为公共子序列。

# 使用动态规划进行 DNA 测序

我们刚刚看到了如何找到最长公共子序列。使用相同的原理，我们可以实现 DNA 或蛋白质测序，这对我们解决生物信息学问题非常有帮助。为了对齐目的，我们将使用最流行的算法，即 Needleman-Wunsch 算法。它类似于我们的 LCS 算法，但得分系统不同。在这里，我们对匹配、不匹配和间隙进行不同的得分系统。算法有两部分：一部分是计算可能序列的矩阵，另一部分是回溯找到最佳序列。Needleman-Wunsch 算法为任何给定序列提供了最佳的全局对齐解决方案。由于算法本身有点复杂，加上得分系统的解释，我们可以在许多网站或书籍中找到，我们希望把重点放在算法的实现部分。我们将把问题分为两部分。首先，我们将使用动态规划生成计算表，然后我们将向后跟踪以生成实际的序列对齐。对于我们的实现，我们将使用 1 表示匹配，-1 表示间隙惩罚和不匹配得分。以下是我们实现的第一部分：

```php
define("GC", "-"); 

define("SP", 1); 

define("GP", -1); 

define("MS", -1); 

function NWSquencing(string $s1, string $s2) { 

    $grid = []; 

    $M = strlen($s1); 

    $N = strlen($s2); 

    for ($i = 0; $i <= $N; $i++) { 

    $grid[$i] = []; 

      for ($j = 0; $j <= $M; $j++) { 

          $grid[$i][$j] = null; 

      } 

    } 

    $grid[0][0] = 0; 

    for ($i = 1; $i <= $M; $i++) { 

        $grid[0][$i] = -1 * $i; 

    } 

    for ($i = 1; $i <= $N; $i++) { 

        $grid[$i][0] = -1 * $i; 

    } 

    for ($i = 1; $i <= $N; $i++) { 

      for ($j = 1; $j <= $M; $j++) { 

          $grid[$i][$j] = max( 

            $grid[$i - 1][$j - 1] + ($s2[$i - 1] === $s1[$j - 1] ? SP : 

              MS), $grid[$i - 1][$j] + GP, $grid[$i][$j - 1] + GP 

          ); 

      } 

    } 

    printSequence($grid, $s1, $s2, $M, $N); 

} 

```

在这里，我们创建了一个大小为 M，N 的二维数组，其中 M 是字符串#1 的大小，N 是字符串#2 的大小。我们将网格的第一行和第一列初始化为递减顺序的负值。我们将索引乘以���隙惩罚来实现这种行为。在这里，我们的常数 SP 表示匹配得分点，MS 表示不匹配得分，GP 表示间隙惩罚，GC 表示间隙字符，在序列打印时我们将使用它。在动态规划结束时，矩阵将被生成。让我们考虑以下两个字符串：

```php
$X = "GAATTCAGTTA"; 

$Y = "GGATCGA"; 

```

然后，运行 Needleman 算法后，我们的表将如下所示：

|  |  | G | A | A | T | T | C | A | G | T | T | A |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
|  | 0 | -1 | -2 | -3 | -4 | -5 | -6 | -7 | -8 | -9 | -10 | -11 |
| G | -1 | 1 | 0 | -1 | -2 | -3 | -4 | -5 | -6 | -7 | -8 | -9 |
| G | -2 | 0 | 0 | -1 | -2 | -3 | -4 | -5 | -4 | -5 | -6 | -7 |
| A | -3 | -1 | 1 | 1 | 0 | -1 | -2 | -3 | -4 | -5 | -6 | -5 |
| T | -4 | -2 | 0 | 0 | 2 | 1 | 0 | -1 | -2 | -3 | -4 | -5 |
| C | -5 | -3 | -1 | -1 | 1 | 1 | 2 | 1 | 0 | -1 | -2 | -3 |
| G | -6 | -4 | -2 | -2 | 0 | 0 | 1 | 1 | 2 | 1 | 0 | -1 |
| A | -7 | -5 | -3 | -1 | -1 | -1 | 0 | 2 | 1 | 1 | 0 | 1 |

现在，使用这个得分表，我们可以找出实际的序列。在这里，我们将从表中的右下角单元格开始，并考虑顶部单元格、左侧单元格和对角线单元格的值。如果三个单元格中的最大值是顶部单元格，则顶部字符串需要插入间隙字符(-)。如果最大值是对角线单元格，则匹配的可能性更大。因此，我们可以比较两个字符串的两个字符，如果它们匹配，则可以放置一条竖线或管字符来显示对齐。以下是序列函数的样子：

```php
function printSequence($grid, $s1, $s2, $j, $i) { 

    $sq1 = []; 

    $sq2 = []; 

    $sq3 = []; 

    do { 

    $t = $grid[$i - 1][$j]; 

    $d = $grid[$i - 1][$j - 1]; 

    $l = $grid[$i][$j - 1]; 

    $max = max($t, $d, $l); 

    switch ($max) { 

        case $d: 

        $j--; 

        $i--; 

          array_push($sq1, $s1[$j]); 

          array_push($sq2, $s2[$i]); 

          if ($s1[$j] == $s2[$i]) 

              array_push($sq3, "|"); 

          else 

              array_push($sq3, " "); 

        break; 

        case $t: 

        $i--; 

          array_push($sq1, GC); 

          array_push($sq2, $s2[$i]); 

          array_push($sq3, " "); 

        break; 

        case $l: 

          $j--; 

          array_push($sq1, $s1[$j]); 

          array_push($sq2, GC); 

          array_push($sq3, " "); 

        break; 

    } 

    } while ($i > 0 && $j > 0); 

    echo implode("", array_reverse($sq1)) . "\n"; 

    echo implode("", array_reverse($sq3)) . "\n"; 

    echo implode("", array_reverse($sq2)) . "\n"; 

} 

```

由于我们是从后往前开始，慢慢向前移动，我们使用数组推送来保持对齐顺序。然后，我们通过反转数组来打印数组。算法的复杂度为 O(M*N)。如果我们为我们的两个字符串`$X`和`$Y`调用`NWSquencing`，输出将如下所示：

```php
G-AATTCAGTTA

| | | | |  |

GGA-T-C-G--A

```

# 回溯解决难题问题

回溯是一种递归算法策略，当找不到结果时我们回溯并继续在其他可能的方式中搜索解决方案。回溯是解决许多著名问题的一种流行方式，尤其是国际象棋、数独、填字游戏等。由于递归是回溯的关键组成部分，我们需要确保我们的问题可以分解为子问题，并将递归应用到这些子问题中。在本节中，我们将使用回溯来解决最受欢迎的游戏之一，数独。

在数独中，我们有一个部分填充的盒子，大小为 3X3。游戏的规则是在每个单元格中放置 1 到 9 的数字，其中相同的数字不能存在于同一行或同一列。因此，在 9X9 单元格中，每个数字 1 到 9 将分别出现一次，每行和每列都是如此。

|  |  | 7 |  | 3 |  | 8 |  |  |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
|  |  |  | 2 |  | 5 |  |  |  |
| 4 |  |  | 9 |  | 6 |  |  | 1 |
|  | 4 | 3 |  |  |  | 2 | 1 |  |
| 1 |  |  |  |  |  |  |  | 5 |
|  | 5 | 8 |  |  |  | 6 | 7 |  |
| 5 |  |  | 1 |  | 8 |  |  | 9 |
|  |  |  | 5 |  | 3 |  |  |  |
|  |  | 2 |  | 9 |  | 5 |  |  |

例如，在前面的数独板中，第一列有 4、1、5，第一行有 7、3、8。因此，我们不能在左上角的第一个空单元格中使用这六个数字中的任何一个。因此，可能的数字可以是 2、6 和 9。我们不知道这些数字中的哪一个将满足解决方案。我们可以选择两个数字放在第一个单元格中，然后开始寻找其余空单元格的值。这将持续到所有单元格都填满，或者仍然有一种方法可以在空单元格中放置一个数字而不违反游戏原则。如果没有解决方案，我们将回溯并回到 2，再用下一个可能的选项 6 替换它，并运行相同的递归方式找到其他空单元格的数字。这将持续到解决数独。让我们写一些递归代码来解决数独：

```php
define("N", 9); 

define("UNASSIGNED", 0); 

function FindUnassignedLocation(array &$grid, int &$row,  

int &$col): bool { 

    for ($row = 0; $row < N; $row++) 

      for ($col = 0; $col < N; $col++) 

          if ($grid[$row][$col] == UNASSIGNED) 

          return true; 

    return false; 

} 

function UsedInRow(array &$grid, int $row, int $num): bool { 

    return in_array($num, $grid[$row]); 

} 

function UsedInColumn(array &$grid, int $col, int $num): bool { 

    return in_array($num, array_column($grid, $col)); 

} 

function UsedInBox(array &$grid, int $boxStartRow,  

int $boxStartCol, int $num): bool { 

    for ($row = 0; $row < 3; $row++) 

    for ($col = 0; $col < 3; $col++) 

if ($grid[$row + $boxStartRow][$col + $boxStartCol] == $num) 

        return true; 

    return false; 

} 

function isSafe(array $grid, int $row, int $col, int $num): bool { 

    return !UsedInRow($grid, $row, $num) && 

        !UsedInColumn($grid, $col, $num) && 

        !UsedInBox($grid, $row - $row % 3, $col - $col % 3, $num); 

} 

```

在这里，我们可以看到实现`Sudoku`函数所需的所有辅助函数。首先，我们定义了网格的最大大小以及未分配单元格指示符，在这种情况下为 0。我们的第一个函数是在 9X9 网格中查找任何未分配的位置，从左上角单元格开始，逐行搜索空单元格。然后，我们有三个函数来检查数字是否在特定行、列或 3X3 框中使用。如果数字在行、列或框中没有使用，我们可以将其用作单元格中的可能值，这就是为什么在`isSafe`函数检查中我们返回 true。如果它在这些地方的任何一个中使用，函数将返回 false。现在，我们准备实现解决数独的递归函数：

```php
function SolveSudoku(array &$grid): bool { 

    $row = $col = 0; 

    if (!FindUnassignedLocation($grid, $row, $col)) 

        return true; // success! no empty space 

    for ($num = 1; $num <= N; $num++) { 

      if (isSafe($grid, $row, $col, $num)) { 

          $grid[$row][$col] = $num; // make assignment 

          if (SolveSudoku($grid)) 

          return true;  // return, if success 

          $grid[$row][$col] = UNASSIGNED;  // failure 

      } 

    } 

    return false; // triggers backtracking 

} 

function printGrid(array $grid) { 

    foreach ($grid as $row) { 

        echo implode("", $row) . "\n"; 

    } 

}

```

`SolveSudoku`函数是不言自明的。在这里，我们访问了一个单元格，如果单元格是空的，就在单元格中放入一个临时数字，从 1 到 9 的任意数字。然后，我们检查数字是否在行、列或 3X3 矩阵中是多余的。如果不冲突，我们将数字保留在单元格中并移动到下一个空单元格。我们通过递归来做到这一点，这样如果需要的话，我们可以跟踪回来并在冲突的情况下更改单元格中的值。这将持续到找到解决方案为止。我们还添加了一个`printGrid`函数，在命令行中打印给定的网格。现在让我们用这个示例数独矩阵运行代码：

```php
$grid = [ 

    [0, 0, 7, 0, 3, 0, 8, 0, 0], 

    [0, 0, 0, 2, 0, 5, 0, 0, 0], 

    [4, 0, 0, 9, 0, 6, 0, 0, 1], 

    [0, 4, 3, 0, 0, 0, 2, 1, 0], 

    [1, 0, 0, 0, 0, 0, 0, 0, 5], 

    [0, 5, 8, 0, 0, 0, 6, 7, 0], 

    [5, 0, 0, 1, 0, 8, 0, 0, 9], 

    [0, 0, 0, 5, 0, 3, 0, 0, 0], 

    [0, 0, 2, 0, 9, 0, 5, 0, 0] 

]; 

if (SolveSudoku($grid) == true) 

    printGrid($grid); 

else 

    echo "No solution exists"; 

```

我们使用了一个二维数组来表示我们的数独矩阵。如果我们运行代码，它将在命令行中产生以下输出：

```php
297431856

361285497

485976321

743659218

126847935

958312674

534128769

879563142

612794583

```

或者，如果我们以一个漂亮的数独矩阵呈现，它将看起来像这样：

| 2 | 9 | 7 | 4 | 3 | 1 | 8 | 5 | 6 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 3 | 6 | 1 | 2 | 8 | 5 | 4 | 9 | 7 |
| 4 | 8 | 5 | 9 | 7 | 6 | 3 | 2 | 1 |
| 7 | 4 | 3 | 6 | 5 | 9 | 2 | 1 | 8 |
| 1 | 2 | 6 | 8 | 4 | 7 | 9 | 3 | 5 |
| 9 | 5 | 8 | 3 | 1 | 2 | 6 | 7 | 4 |
| 5 | 3 | 4 | 1 | 2 | 8 | 7 | 6 | 9 |
| 8 | 7 | 9 | 5 | 6 | 3 | 1 | 4 | 2 |
| 6 | 1 | 2 | 7 | 9 | 4 | 5 | 8 | 3 |

回溯法可以非常有用地找到解决方案，找到路径或解决游戏问题。有许多关于回溯法的在线参考资料，对我们非常有用。

# 协同过滤推荐系统

推荐系统今天在互联网上随处可见。从电子商务网站到餐馆、酒店、门票、活动等等，都向我们推荐。我们是否曾经问过自己，他们是如何知道什么对我们最好？他们是如何计算出显示我们可能喜欢的物品的？答案是大多数网站使用协同过滤（CF）来推荐。协同过滤是通过分析其他用户的选择或偏好（协同）来自动预测（过滤）用户兴趣的过程。我们将使用皮尔逊相关方法构建一个简单的推荐系统，在这个方法中，计算两个人之间的相似度得分在-1 到+1 的范围内。如果相似度得分是+1，那么意味着两个人完全匹配。如果相似度得分是 0，那么意味着他们之间没有相似之处，如果得分是-1，那么他们是负相关的。通常，得分大多是分数形式。

皮尔逊相关是使用以下公式计算的：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00092.jpg)

这里，*x*表示第一个人的偏好，y 表示第二个人的偏好，N 表示偏好中的项目数，这些项目在*x*和*y*之间是共同的。现在让我们为达卡的餐馆实现一个样本评论系统。有一些评论者已经评论了一些餐馆。其中一些是共同的，一些不是。我们的工作将是根据其他人的评论为*X*找到一个推荐。我们的评论看起来像这样：

```php
$reviews = []; 

$reviews['Adiyan'] = ["McDonalds" => 5, "KFC" => 5, "Pizza Hut" => 4.5, "Burger King" => 4.7, "American Burger" => 3.5, "Pizza Roma" => 2.5]; 

$reviews['Mikhael'] = ["McDonalds" => 3, "KFC" => 4, "Pizza Hut" => 3.5, "Burger King" => 4, "American Burger" => 4, "Jafran" => 4]; 

$reviews['Zayeed'] = ["McDonalds" => 5, "KFC" => 4, "Pizza Hut" => 2.5, "Burger King" => 4.5, "American Burger" => 3.5, "Sbarro" => 2]; 

$reviews['Arush'] = ["KFC" => 4.5, "Pizza Hut" => 3, "Burger King" => 4, "American Burger" => 3, "Jafran" => 2.5, "FFC" => 3.5]; 

$reviews['Tajwar'] = ["Burger King" => 3, "American Burger" => 2, "KFC" => 2.5, "Pizza Hut" => 3, "Pizza Roma" => 2.5, "FFC" => 3]; 

$reviews['Aayan'] = [ "KFC" => 5, "Pizza Hut" => 4, "Pizza Roma" => 4.5, "FFC" => 4]; 

```

现在，基于这个结构，我们可以编写我们的皮尔逊相关计算器之间的计算。这是实现：

```php
function pearsonScore(array $reviews, string $person1, string $person2): float { 

$commonItems = array(); 

foreach ($reviews[$person1] as $restaurant1 => $rating) { 

    foreach ($reviews[$person2] as $restaurant2 => $rating) { 

        if ($restaurant1 == $restaurant2) { 

          $commonItems[$restaurant1] = 1; 

        } 

    } 

} 

$n = count($commonItems); 

if ($n == 0) 

    return 0.0; 

    $sum1 = 0; 

    $sum2 = 0; 

    $sqrSum1 = 0; 

    $sqrSum2 = 0; 

    $pSum = 0; 

    foreach ($commonItems as $restaurant => $common) { 

      $sum1 += $reviews[$person1][$restaurant]; 

      $sum2 += $reviews[$person2][$restaurant]; 

      $sqrSum1 += $reviews[$person1][$restaurant] ** 2; 

      $sqrSum2 += $reviews[$person2][$restaurant] ** 2; 

      $pSum += $reviews[$person1][$restaurant] *  

      $reviews[$person2][$restaurant]; 

    } 

    $num = $pSum - (($sum1 * $sum2) / $n); 

    $den = sqrt(($sqrSum1 - (($sum1 ** 2) / $n))  

      * ($sqrSum2 - (($sum2 ** 2) / $n))); 

    if ($den == 0) { 

      $pearsonCorrelation = 0; 

    } else { 

      $pearsonCorrelation = $num / $den; 

    } 

 return (float) $pearsonCorrelation; 

} 

```

在这里，我们刚刚实现了我们为皮尔逊相关计算器所展示的方程。现在，我们将根据皮尔逊得分编写推荐函数：

```php
function getRecommendations(array $reviews, string $person): array { 

    $calculation = []; 

    foreach ($reviews as $reviewer => $restaurants) { 

    $similarityScore = pearsonScore($reviews, $person, $reviewer); 

        if ($person == $reviewer || $similarityScore <= 0) { 

            continue; 

        } 

        foreach ($restaurants as $restaurant => $rating) { 

            if (!array_key_exists($restaurant, $reviews[$person])) { 

                if (!array_key_exists($restaurant, $calculation)) { 

                    $calculation[$restaurant] = []; 

                    $calculation[$restaurant]['Total'] = 0; 

                    $calculation[$restaurant]['SimilarityTotal'] = 0; 

                } 

            $calculation[$restaurant]['Total'] += $similarityScore * 

              $rating; 

            $calculation[$restaurant]['SimilarityTotal'] += 

              $similarityScore; 

            } 

        } 

    } 

    $recommendations = []; 

    foreach ($calculation as $restaurant => $values) { 

    $recommendations[$restaurant] = $calculation[$restaurant]['Total']  

      / $calculation[$restaurant]['SimilarityTotal']; 

    } 

    arsort($recommendations); 

    return $recommendations; 

} 

```

在前面的函数中，我们计算了每个评论者之间的相似度分数，并加权了他们的评论。基于最高分，我们展示了对评论者的推荐。让我们运行以下代码来获得一些推荐：

```php
$person = 'Arush'; 

echo 'Restaurant recommendations for ' . $person . "\n"; 

$recommendations = getRecommendations($reviews, $person); 

foreach ($recommendations as $restaturant => $score) { 

    echo $restaturant . " \n"; 

} 

```

这将产生以下输出：

```php
Restaurant recommendations for Arush

McDonalds

Pizza Roma

Sbarro

```

我们可以使用皮尔逊相关评分系统来推荐物品或向用户展示如何获得更好的评论。还有许多其他方法可以使协同过滤工作，但这超出了本书的范围。

# 使用布隆过滤器和稀疏矩��

稀疏矩阵可以用作高效的数据结构。稀疏矩阵的 0 值比实际值多。例如，一个 100 X 100 的矩阵可能有 10,000 个单元。现在，在这 10,000 个单元中，只有 100 个有值；其余都是 0。除了这 100 个值，其余的单元都被默认值 0 占据，并且它们占据相同的字节大小来存储值 0 以表示空单元。这是对空间的巨大浪费，我们可以使用稀疏矩阵来减少它。我们可以使用不同的技术将值存储到稀疏矩阵中的一个单独的矩阵中，这将非常精简并且不会占用任何不必要的空间。我们还可以使用链表来表示稀疏矩阵。这是稀疏矩阵的一个例子：

|

&#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 1 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124;

&#124; 1 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124;

&#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 2 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124;

&#124; 0 &#124; 0 &#124; 2 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124;

&#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 1 &#124; 0 &#124; 0 &#124; 0 &#124;

&#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 2 &#124; 0 &#124; 0 &#124;

&#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 1 &#124; 0 &#124; 0 &#124; 0 &#124;

&#124; 1 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124;

|

&#124; **行** &#124; **列** &#124; **值** &#124;

&#124; 0 &#124; 5 &#124; 1 &#124;

&#124; 1 &#124; 0 &#124; 1 &#124;

&#124; 2 &#124; 4 &#124; 2 &#124;

&#124; 3 &#124; 2 &#124; 2 &#124;

&#124; 4 &#124; 6 &#124; 1 &#124;

&#124; 5 &#124; 7 &#124; 2 &#124;

&#124; 6 &#124; 6 &#124; 1 &#124;

&#124; 7 &#124; 1 &#124; 1 &#124;

|

由于 PHP 数组的性质是动态的，因此在 PHP 中稀疏矩阵的最佳方法将只使用具有值的索引；其他索引根本不使用。当我们使用单元格时，我们可以检查单元格是否有任何值；否则，将使用默认值 0，就像下面的例子所示：

```php
$sparseArray = []; 

$sparseArray[0][5] = 1; 

$sparseArray[1][0] = 1; 

$sparseArray[2][4] = 2; 

$sparseArray[3][2] = 2; 

$sparseArray[4][6] = 1; 

$sparseArray[5][7] = 2; 

$sparseArray[6][6] = 1; 

$sparseArray[7][1] = 1; 

function getSparseValue(array $array, int $i, int $j): int { 

    if (isset($array[$i][$j])) 

        return $array[$i][$j]; 

    else 

        return 0; 

} 

echo getSparseValue($sparseArray, 0, 2) . "\n"; 

echo getSparseValue($sparseArray, 7, 1) . "\n"; 

echo getSparseValue($sparseArray, 8, 8) . "\n"; 

```

这将在命令行中产生以下输出：

```php
0

1

0

```

当我们有一个大型数据集时，在数据集中查找可能非常耗时和昂贵。假设我们有 1000 万个电话号码的数据集，我们想要搜索一个特定的电话号码。这可以很容易地通过数据库查询来完成。但是，如果是 10 亿个电话号码呢？从数据库中查找仍然会更快吗？这样一个庞大的数据库可能会导致性能下降的查找。为了解决这个问题，一个高效的方法可以是使用布隆过滤器。

布隆过滤器是一种高效的、概率性的数据结构，用于确定特定项是否属于集合。它返回两个值：“可能在集合中”和“绝对不在集合中”。如果一个项不属于集合，布隆过滤器返回 false。但是，如果返回 true，则该项可能在集合中，也可能不在集合中。这个原因在这里描述。

一般来说，布隆过滤器是一个大小为 m 的位数组，所有初始值都是 0。有 k 个不同的“哈希”函数，它将一个项转换为一个哈希整数值，该值被映射到位数组中。这个哈希值可以在 0 到 m 之间，因为 m 是位数组的最大大小。哈希函数类似于 md5，sha1，crc32 等，但它们非常快速和高效。通常在布隆过滤器 fnv，murmur，Siphash 等中使用哈希函数。让我们以初始值为 0 的 16（16+1 个单元）位布隆过滤器为例：

| &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; |
| --- |

假设我们有两个哈希函数 k1 和 k2，将我们的项转换为 0 到 16 之间的整数值。让我们要存储在布隆过滤器中的第一个项是“PHP”。然后，我们的哈希函数将返回以下值：

```php
k1("PHP") = 5 

k2("PHP") = 9 

```

两个哈希函数返回了两个不同的值。现在我们可以在位数组中放置 1 来标记它。位数组现在看起来是这样的：

| &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 1 &#124; 0 &#124; 0 &#124; 0 &#124; 1 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; |
| --- |

现在让我们在列表中添加另一个项，例如“algorithm”。假设我们的哈希函数将返回以下值：

```php
k1("algorithm") = 2 

k2("algorithm") = 5 

```

由于我们可以看到 5 已经被另一个项标记，我们不���再次标记它。现��，位数组将如下所示：

| &#124; 0 &#124; 0 &#124; 1 &#124; 0 &#124; 0 &#124; 1 &#124; 0 &#124; 0 &#124; 0 &#124; 1 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; 0 &#124; |
| --- |

例如，现在，我们想要检查一个名为“error”的项，它被哈希为以下值：

```php
k1("error") = 2 

k2("error") = 9 

```

正如我们所看到的，我们的哈希函数 k1 和 k2 为字符串“error”返回了一个哈希值，而该值不在数组中。因此，这肯定是一个错误，如果我们���哈希函数只有少数，我们期望会有这样的错误。哈希函数越多，错误就越少，因为不同的哈希函数将返回不同的值。错误率、哈希函数的数量和布隆过滤器的大小之间存在关系。例如，一个包含 5000 个项和 0.0001 错误率的布隆过滤器将需要大约 14 个哈希函数和大约 96000 位。我们可以从在线布隆过滤器计算器（例如[`krisives.github.io/bloom-calculator/`](https://krisives.github.io/bloom-calculator/)）中获得这样的数字。

# 总结

在本章中，我们已经看到了许多先进的算法和技术，可以用来解决不同类型的问题。有许多好的资源可供学习这些主题。动态规划是一个如此重要的主题，可以在几章中进行介绍，或者有一个单独的书籍来介绍它。我们试图解释了一些主题，但还有更多可以探索的。您还学习了稀疏矩阵和布隆过滤器，它们可以用于大数据块的高效数据存储。我们可以在需要时使用这些数据结构概念。现在，随着我们接近本书的结尾，我们将用一些可用的库、函数和参考资料来总结我们关于 PHP 7 中数据结构和算法的讨论。
