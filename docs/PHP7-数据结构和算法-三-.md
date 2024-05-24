# PHP7 数据结构和算法（三）

> 原文：[`zh.annas-archive.org/md5/eb90534f20ff388513beb1e54fb823ef`](https://zh.annas-archive.org/md5/eb90534f20ff388513beb1e54fb823ef)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：使用排序算法

排序是计算机编程中最常用的算法之一。即使在日常生活中，如果事物没有排序，我们也会遇到困难。排序可以为集合中的项目提供更快的搜索或排序方式。排序可以以许多不同的方式进行，例如按升序或降序进行。排序也可以基于数据类型进行。例如，对名称集合进行排序将需要按字典顺序排序而不是按数字排序。由于排序对其他数据结构及其效率起着重要作用，因此有许多不同的排序算法可供选择。在本章中，我们将探讨一些最流行的排序算法，以及它们的复杂性和用途。

# 理解排序及其类型

排序意味着数据的排序顺序。通常，我们的数据是未排序的，这意味着我们需要一种排序方式。通常，排序是通过将不同的元素进行比较并得出排名来完成的。在大多数情况下，如果没有比较，我们无法决定排序部分。比较之后，我们还需要交换元素，以便重新排序它们。一个好的排序算法具有最小数量的比较和交换的特点。还有一种非比较排序，它不需要比较就可以对项目列表进行排序。我们也将在本章中探讨这些算法。

根据数据集的类型、方向、计算复杂性、内存使用、空间使用等不同标准，排序可以分为不同类型。以下是本章中我们将探讨的一些排序算法：

+   冒泡排序

+   插入排序

+   选择排序

+   快速排序

+   归并排序

+   桶排序

我们将把讨论限制在上面的列表中，因为它们是最常用的排序算法，可以根据不同的标准进行分组和分类，比如简单排序、高效排序、分布排序等等。我们现在将探讨每种排序功能、它们的实现以及复杂性分析，以及它们的优缺点。让我们从最常用的排序算法——冒泡排序开始。

# 理解冒泡排序

冒泡排序是编程世界中最常用的排序算法。大多数程序员都是从这个算法开始学习排序的。它是一种基于比较的排序算法，通常被认为是最低效的排序算法之一。它需要最大数量的比较，平均情况和最坏情况的复杂性是相同的。

在冒泡排序中，列表的每个项目都与其余项目进行比较，并在需要时进行交换。这对列表中的每个项目都会继续进行。我们可以按升序或降序进行排序。以下是冒泡排序的伪算法：

```php
procedure bubbleSort( A : list of sortable items ) 

   n = length(A) 

   for i = 0 to n inclusive do  

     for j = 0 to n-1 inclusive do 

       if A[j] > A[j+1] then 

         swap( A[j], A[j+1] ) 

       end if 

     end for 

   end for 

end procedure

```

从上面的伪代码中可以看出，我们运行一个循环来确保迭代列表的每个项目。内部循环确保一旦我们指向一个项目，我们就会将该项目与列表中的其他项目进行比较。根据我们的偏好，我们可以交换这两个项目。以下图片显示了对列表中的一个项目进行排序的单次迭代。假设我们的列表包含以下项目：20，45，93，67，10，97，52，88，33，92。对于第一次通过（迭代）来排序第一个项目，将采取以下步骤：

（图片）

如果我们检查上面的图片，我们可以看到我们正在比较两个数字，然后决定是否要交换/交换项目。背景颜色的项目显示了我们正在比较的两个项目。正如我们所看到的，外部循环的第一次迭代导致将最顶部的项目存储在列表中的最顶部位置。这将持续进行，直到我们迭代列表中的每个项目。

现在让我们使用 PHP 来实现冒泡排序算法。

# 使用 PHP 实现冒泡排序

由于我们假设未排序的数字将在一个列表中，我们可以使用 PHP 数组来表示未排序数字的列表。由于数组既有索引又有值，我们可以利用数组来轻松地根据位置迭代每个项目，并在适用的情况下进行交换。根据我们的伪代码，代码将如下所示：

```php
function bubbleSort(array $arr): array { 

    $len = count($arr); 

    for ($i = 0; $i < $len; $i++) { 

      for ($j = 0; $j < $len - 1; $j++) { 

          if ($arr[$j] > $arr[$j + 1]) { 

            $tmp = $arr[$j + 1]; 

            $arr[$j + 1] = $arr[$j]; 

            $arr[$j] = $tmp; 

          } 

      } 

    }     

    return $arr; 

}

```

正如我们所看到的，我们使用两个`for`循环来迭代每个项目并与其余项目进行比较。交换是在以下行中完成的：

```php
$tmp = $arr[$j + 1];

$arr[$j + 1] = $arr[$j];

$arr[$j] = $tmp;

```

首先，我们将第二个值分配给名为`$tmp`的临时变量。然后，我们将第一个值分配给第二个值，并重新分配临时值给第一个值。这被称为使用第三个或临时变量交换两个变量。

只有在第一个值大于第二个值时才进行交换。否则，我们就忽略。图像右侧的注释显示了是否发生了交换。如果我们想按降序（较大的数字优先）对其进行排序，那么我们只需修改`if`条件如下：

```php
if ($arr[$j] < $arr[$j + 1]) {

}

```

现在，让我们按照以下方式运行代码：

```php
$arr = [20, 45, 93, 67, 10, 97, 52, 88, 33, 92]; 

$sortedArray = bubbleSort($arr); 

echo implode(",", $sortedArray); 

```

这将产生以下输出：

```php
10,20,33,45,52,67,88,92,93,97

```

因此，我们可以看到数组使用冒泡排序算法进行了排序。现在，让我们讨论算法的复杂性。

# 冒泡排序的复杂性

对于第一次通过，在最坏的情况下，我们必须进行*n-1*次比较和交换。对于第*n-1*次通过，在最坏的情况下，我们只需要进行一次比较和交换。因此，如果我们一步一步地写出来，我们会看到：

*复杂度= n - 1 + n - 2 + .......... + 2 + 1 = n * ( n - 1)/2 = O(n² )*

因此，冒泡排序的复杂度是`O(n² )`。然而，分配临时变量、交换、遍历内部循环等都需要一些常数时间。我们可以忽略它们，因为它们是常数。

这是冒泡排序的时间复杂度表，包括最佳情况、平均情况和最坏情况：

| 最佳时间复杂度 | `Ω(n)` |
| --- | --- |
| 最坏时间复杂度为`O(n² )` |
| 平均时间复杂度 | `Θ(n² )` |
| 空间复杂度（最坏情况） | `O(1)` |

尽管冒泡排序的时间复杂度为`O(n² )`，我们仍然可以应用一些改进来减少比较和交换的次数。现在让我们探讨这些选项。最佳时间为`Ω(n)`，因为我们至少需要一个内部循环来运行以找出数组已经排序。

# 改进冒泡排序算法

冒泡排序最重要的一个方面是，对于外部循环中的每次迭代，至少会有一次交换。如果没有交换，那么列表已经排序。我们可以利用这一改进在我们的伪代码中重新定义它：

```php
procedure bubbleSort( A : list of sortable items ) 

   n = length(A) 

   for i = 1 to n inclusive do  

     swapped = false 

     for j = 1 to n-1 inclusive do 

       if A[j] > A[j+1] then 

         swap( A[j], A[j+1] ) 

         swapped = true 

       end if 

     end for 

     if swapped is false 

        break 

     end if 

   end for 

end procedure

```

正如我们现在所看到的，我们现在为每次迭代设置了一个`false`标志，并且我们期望，在内部迭代中，标志将被设置为`true`。如果在内部循环完成后标志仍然为 false，则我们可以中断循环，以便标记列表为已排序。这是改进算法的实现：

```php
function bubbleSort(array $arr): array { 

    $len = count($arr); 

    for ($i = 0; $i < $len; $i++) { 

      $swapped = FALSE; 

      for ($j = 0; $j < $len - 1; $j++) { 

          if ($arr[$j] > $arr[$j + 1]) { 

            $tmp = $arr[$j + 1]; 

            $arr[$j + 1] = $arr[$j]; 

            $arr[$j] = $tmp; 

            $swapped = TRUE; 

          } 

      } 

         if(! $swapped) break; 

    }     

    return $arr; 

} 

```

另一个观察是，在第一次迭代中，顶部项目被放置在数组的右侧。在第二次循环中，第二个顶部项目将位于数组的右侧第二个位置。如果我们可以想象每次迭代后，第 i 个单元格已经存储了已排序的项目，那么就没有必要访问该索引并进行比较。因此，我们可以减少外部迭代次数和内部迭代次数，并大幅减少比较。这是我们提出的第二个改进的伪代码：

```php
procedure bubbleSort( A : list of sortable items ) 

   n = length(A) 

   for i = 1 to n inclusive do  

     swapped = false 

     for j = 1 to n-i-1 inclusive do 

       if A[j] > A[j+1] then 

         swap( A[j], A[j+1] ) 

         swapped = true 

       end if 

     end for 

     if swapped is false 

        break 

     end if 

   end for 

end procedure 

```

现在，让我们用 PHP 实现最终改进的版本：

```php
function bubbleSort(array $arr): array {

    $len = count($arr); 

    for ($i = 0; $i < $len; $i++) { 

      $swapped = FALSE; 

      for ($j = 0; $j < $len - $i - 1; $j++) { 

          if ($arr[$j] > $arr[$j + 1]) { 

            $tmp = $arr[$j + 1]; 

            $arr[$j + 1] = $arr[$j]; 

            $arr[$j] = $tmp; 

            $swapped = TRUE; 

          } 

      } 

      if(! $swapped) break; 

    }     

    return $arr; 

} 

```

如果我们看一下前面代码中的内部循环，唯一的区别是 `$j < $len - $i - 1` ；其他部分与第一次改进相同。所以，基本上，对于我们的 **20** , **45** , **93** , **67** , **10** , **97** , **52** , **88** , **33** , **92** 列表，我们可以很容易地说，在第一次迭代之后，顶部的数字 **97** 将不会被考虑进行第二次迭代比较。同样， **93** 也将不会被考虑进行第三次迭代，就像下面的图片一样：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00058.gif)

如果我们看前面的图片，立即冒出的问题是“**92** 已经排序了吗？我们需要再次比较所有数字并标记 **92** 已经在其位置上排序了吗？”是的，我们是对的。这是一个有效的问题。这意味着我们可以知道，在内部循环中我们上次交换的位置；之后，数组已经排序。因此，我们可以为下一个循环设置一个边界，直到那时，只比较我们设置的边界之前的部分。以下是此操作的伪代码：

```php
procedure bubbleSort( A : list of sortable items )

   n = length(A)

   bound = n -1

   for i = 1 to n inclusive do

     swapped = false

     newbound = 0

     for j = 1 to bound inclusive do

       if A[j] > A[j+1] then

         swap( A[j], A[j+1] )

            swapped = true

            newbound = j

       end if

     end for

     bound = newbound

     if swapped is false

        break

     end if

   end for

end procedure

```

在这里，我们在每次内部循环完成后设置边界，并确保我们不会进行不必要的迭代。以下是使用前面伪代码的实际 PHP 代码：

```php
function bubbleSort(array $arr): array {

    $len = count($arr);

    $count = 0;

    $bound = $len-1;

    for ($i = 0; $i < $len; $i++) {

     $swapped = FALSE;

     $newBound = 0;

      for ($j = 0; $j < $bound; $j++) {

          $count++;

          if ($arr[$j] > $arr[$j + 1]) {

            $tmp = $arr[$j + 1];

            $arr[$j + 1] = $arr[$j];

            $arr[$j] = $tmp;

            $swapped = TRUE;

            $newBound = $j;

          }

      }

     $bound = $newBound;

     if(! $swapped) break;

    }

    echo $count."\n";

    return $arr;

}

```

我们已经看到了冒泡排序实现的不同变体，但输出始终相同：**10** , **20** , **33** , **45** , **52** , **67** , **88** , **92** , **93** , **97** 。如果是这种情况，那么我们如何确定我们的改进实际上对算法产生了一些影响呢？以下是我们的初始列表 20, 45, 93, 67, 10, 97, 52, 88, 33, 92 的所有四种实现的比较次数的一些统计数据：

| **解决方案** | **比较次数** |
| --- | --- |
| 常规冒泡排序 | 90 |
| 第一次改进后 | 63 |
| 第二次改进后 | 42 |
| 第三次改进后 | 38 |

正如我们所看到的，我们通过改进将比较次数从 **90** 减少到 **38** 。因此，我们可以肯定地通过一些改进来提高算法，以减少所需的比较次数。

# 理解选择排序

选择排序是另一种基于比较的排序算法，看起来类似于冒泡排序。最大的区别在于它进行的交换次数比冒泡排序少。在选择排序中，我们首先找到数组的最小/最大项，并将其放在第一个位置。如果我们按降序排序，那么我们将从数组中取得最大值。对于升序排序，我们将取得最小值。在第二次迭代中，我们将找到数组的第二大或第二小值，并将其放在第二个位置。这样一直进行，直到我们将每个数字放在正确排序的位置上。这就是选择排序。选择排序的伪代码如下所示：

```php
procedure selectionSort( A : list of sortable items )

   n = length(A)

   for i = 1 to n inclusive do

     min = i

     for j = i+1 to n inclusive do

       if A[j] < A[min] then

         min = j

       end if

     end for

     if min != i

        swap(a[i],a[min])

     end if

   end for

end procedure

```

如果我们看前面的算法，我们可以看到，在外部循环的第一次迭代之后，第一个最小项被存储在位置一。在第一次迭代中，我们选择了第一项，然后从剩余项（从 2 到 *n* ）中找到最小值。我们假设第一项是最小值。如果我们找到另一个最小值，我们会标记它的位置，直到我们扫描了剩余列表并找到了一个新的最小值。如果没有找到最小值，那么我们的假设是正确的，那确实是最小值。这里是一个图示，说明了我们的 **20** , **45** , **93** , **67** , **10** , **97** , **52** , **88** , **33** , **92** 数组在选择排序的前两个步骤中的情况：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00059.gif)

如前面的图像所示，我们从列表中的第一个项目**20**开始。然后，我们从数组的其余部分找到最小值**10**。在第一次迭代结束时，我们只交换了两个位置的值（由箭头标记）。因此，在第一次迭代结束时，我们将数组的最小值存储在第一个位置。然后，我们指向下一个项目**45**，并开始从其位置右侧找到与**45**相比的下一个最小项目。我们从剩余项目中找到**20**（如两个箭头所示）。在第二次迭代结束时，我们只是将第二个位置的数字与列表剩余部分中新找到的最小数字进行交换。这将持续到最后一个元素，并且在过程结束时，我们将得到一个排序好的数组列表。现在让我们将伪代码转换为 PHP 代码。

# 实现选择排序

我们将采用与冒泡排序相同的方法，其中我们的实现将以数组作为参数并返回一个排序好的数组。以下是 PHP 中的实现：

```php
function selectionSort(array $arr): array {

    $len = count($arr);

    for ($i = 0; $i < $len; $i++) {

      $min = $i;

      for ($j = $i+1; $j < $len; $j++) {

          if ($arr[$j] < $arr[$min]) {

            $min = $j;

          }

      }

      if ($min != $i) {

          $tmp = $arr[$i];

          $arr[$i] = $arr[$min];

          $arr[$min] = $tmp;

      }

    }

    return $arr;

}

```

正如我们所看到的，这是按升序对数组进行排序的最简单方法。如果要按降序排序，我们只需要将比较`$arr[$j] < $arr[$min]`更改为`$arr[$j] > $arr[$min]`，并将`$min`替换为`$max`。

# 选择排序的复杂度

选择排序看起来也与冒泡排序相似，并且有两个 0 到*n*的`for`循环。冒泡排序和选择排序的基本区别在于，选择排序最多进行*n-1*次交换，而冒泡排序在最坏的情况下可能进行*n*n*次交换。然而，在选择排序中，最佳情况、最坏情况和平均情况的复杂度相似。以下是选择排序的复杂度图表：

| 最佳时间复杂度 | `Ω(n²)` |
| --- | --- |
| 最坏时间复杂度 | `O(n²)` |
| 平均时间复杂度 | `Θ(n²)` |
| 空间复杂度（最坏情况） | `O(1)` |

# 理解插入排序

到目前为止，我们已经看到了两种基于比较的排序算法。现在，我们将探讨另一种排序算法，与前两种相比效率要高一些。我们说的是插入排序。与我们刚刚看到的另外两种排序算法相比，它的实现最简单。如果项目数量较小，插入排序比冒泡排序和选择排序效果更好。如果数据集很大，那么它就会变得效率低下，就像冒泡排序一样。由于插入排序的交换几乎是线性的，建议您使用插入排序而不是冒泡排序和选择排序。

顾名思义，插入排序是根据将数字插入到左侧正确位置的原则工作的。它从数组的第二个项目开始，并检查左侧的项目是否小于当前值。如果是，它会移动项目并将较小的项目存储在其正确的位置。然后，它移动到下一个项目，并且相同的原则一直持续到整个数组排序完成。插入排序的伪代码如下：

```php
procedure insertionSort( A : list of sortable items )

   n = length(A)

   for i = 1 to n inclusive do

     key = A[i]

     j = i - 1

     while j >= 0 and A[j] > key   do

       A[j+1] = A[j]

       j--

     end while

     A[j+1] = key

   end for

end procedure

```

如果我们考虑我们之前用于冒泡排序和选择排序的数字列表，那么我们必须进行插入排序。

我们数组的元素是：**20**，**45**，**93**，**67**，**10**，**97**，**52**，**88**，**33**，**92**。

让我们从第二个项目开始，即**45**。现在，我们将从**45**左边的第一个项目开始，并转到数组的开头，看看左边是否有大于**45**的值。由于只有**20**，因此不需要插入，因为到目前为止的项目已经排序好了（**20**，**45**）。现在，我们将指针移动到**93**，并且再次开始，从数组的左边开始比较并搜索是否有更大的值。由于**45**不大于**93**，因此停在那里，就像之前一样，我们得出前两个项目已经排序好了的结论。现在，我们有前三个项目（**20**，**45**，**93**）排序好了。接下来是**67**，我们再次从左边的数字开始比较。左边的第一个数字是**93**，比较大，因此必须移动一个位置。我们将**93**移动到**67**的位置。然后，我们移动到左边的下一个项目，即**45**。**45**小于**67**，不需要进一步比较。现在，我们将**67**插入到**93**的位置，**93**将移动到**67**的位置。这将一直持续到整个数组排序好。这张图片说明了使用插入排序的完整排序过程的每一步：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00060.gif)

# 实现插入排序

我们将以与其他两种排序类似的方式实现插入排序，但有细微差别。这次，我们将数组作为引用传递。通过这样做，我们将不需要从函数中返回任何值。如果需要的话，我们也可以按值传递参数并在函数结束时返回数组。以下是此代码：

```php
function insertionSort(array &$arr) { 

    $len = count($arr); 

    for ($i = 1; $i < $len; $i++) { 

      $key = $arr[$i]; 

      $j = $i - 1; 

      while($j >= 0 && $arr[$j] > $key) { 

          $arr[$j+1] = $arr[$j]; 

          $j--; 

      }      

      $arr[$j+1] = $key; 

    }     

}

```

参数数组通过引用（`&$arr`）传递给函数。因此，原始数组而不是副本将直接被修改。现在，我们想要运行代码并检查输出。为此，我们必须运行以下代码：

```php
$arr = [20, 45, 93, 67, 10, 97, 52, 88, 33, 92];

insertionSort($arr);

echo implode(",", $arr);

```

这将产生与前两种情况相同的输出。唯一的区别是我们不期望从函数中返回任何数组，并且不将其存储到任何新变量中。

如果我们通过引用传递数组，那么我们就不需要返回数组。传递的数组将在函数内部被修改。我们可以选择如何实现排序。

# 插入排序的复杂性

插入排序的复杂性类似于冒泡排序。与冒泡排序的基本区别在于交换的次数比冒泡排序要少得多。这是插入排序的复杂性：

| 最佳时间复杂度 | `Ω(n)` |
| --- | --- |
| 最坏时间复杂度 | `O(n²)` |
| 平均时间复杂度 | `Θ(n²)` |
| 空间复杂度（最坏情况） | `O(1)` |

# 理解用于排序的分治技术

到目前为止，我们已经探讨了使用完整数字列表的排序选项。结果，我们每次都有一个大的数字列表进行比较。如果我们可以以某种方式使列表变小，这个问题就可以解决。分治法对我们非常有帮助。通过这种方法，我们将问题分解为两个或更多的子问题或集合，然后解决较小的问题，然后将所有这些子问题的结果组合起来得到最终结果。这就是所谓的分治法。

分治法可以让我们有效地解决排序问题，并减少算法的复杂性。最流行的两种排序算法是归并排序和快速排序，它们应用分治算法来对项目列表进行排序，因此被认为是最好的排序算法。现在，我们将在下一节中探讨这两种算法。

# 理解归并排序

正如我们已经知道的，归并排序应用分而治之的方法来解决排序问题，我们需要找出两个过程来解决这个问题。第一个是将问题集分解成足够小的问题，然后合并这些结果。我们将在这里应用递归方法来进行分而治之。以下图像显示了如何采取分而治之的方法。我们现在将考虑一个较小的数字列表**20**，**45**，**93**，**67**，**97**，**52**，**88**，**33**来解释分而治之的部分：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00061.gif)

根据前面的图像，我们现在可以开始准备我们的伪代码，它将有两部分 - 分割和征服。以下是实现这一点的伪代码

`func` mergesort ( A : sortable items 的数组):

```php

     n = length(A)      

     if ( n == 1 ) return a 

     var l1 as array = a[0] ... a[n/2] 

     var l2 as array = a[n/2+1] ... a[n] 

     l1 = mergesort( l1 ) 

     l2 = mergesort( l2 ) 

     return merge( l1, l2 ) 

end func

func merge( a: array, b : array )

     c = array

     while ( a and b have elements )

          if ( a[0] > b[0] )

               add b[0] to the end of c

               remove b[0] from b

          else

               add a[0] to the end of c

               remove a[0] from a

     end while

     while ( a has elements )

          add a[0] to the end of c

          remove a[0] from a

     end while

     while ( b has elements )

          add b[0] to the end of c

          remove b[0] from b

     return c

     end while

end func

```

我们伪代码的第一部分显示了分割过程。我们将数组分割直到达到大小为 1 的程度。然后，我们开始使用合并函数合并结果。在合并函数中，我们有一个数组来存储合并的结果。因此，归并排序实际上比我们迄今为止看到的其他算法具有更多的空间复杂度。现在，让我们开始编码并使用 PHP 实现这个伪代码。

# 实现归并排序

我们首先写出分割部分，然后是合并或征服部分。PHP 有一些内置函数可以拆分数组。我们将使用`array_slice`函数来进行拆分。以下是执行此操作的代码：

```php
function mergeSort(array $arr): array { 

    $len = count($arr); 

    $mid = (int) $len / 2; 

    if ($len == 1) 

         return $arr; 

    $left  = mergeSort(array_slice($arr, 0, $mid)); 

    $right = mergeSort(array_slice($arr, $mid)); 

    return merge($left, $right); 

}

```

从代码中可以看出，我们以递归的方式分割数组，直到数组大小变为 1。当数组大小为 1 时，我们开始向后合并，就像最后一个图像一样。以下是合并函数的代码，它将接受两个数组，并根据我们的伪代码将它们合并成一个：

```php
function merge(array $left, array $right): array { 

    $combined = []; 

    $countLeft = count($left); 

    $countRight = count($right); 

    $leftIndex = $rightIndex = 0; 

    while ($leftIndex < $countLeft && $rightIndex < $countRight) { 

      if ($left[$leftIndex] > $right[$rightIndex]) { 

          $combined[] = $right[$rightIndex]; 

          $rightIndex++; 

      } else { 

          $combined[] = $left[$leftIndex]; 

          $leftIndex++; 

      } 

    } 

    while ($leftIndex < $countLeft) { 

      $combined[] = $left[$leftIndex]; 

      $leftIndex++; 

    } 

    while ($rightIndex < $countRight) { 

      $combined[] = $right[$rightIndex]; 

      $rightIndex++; 

    } 

    return $combined;

}

```

现在代码已经完成，因为我们已经合并了两个提供的数组，并将合并的结果返回给`mergeSort`函数。我们刚刚以递归的方式解决了问题。如果你运行以下代码，你将得到一个按升序排列的项目列表：

```php
$arr = [20, 45, 93, 67, 10, 97, 52, 88, 33, 92];

$arr = mergeSort($arr);

echo implode(",", $arr);

```

现在，让我们探讨归并排序的复杂度。

# 归并排序的复杂度

由于归并排序遵循分而治之的方法，我们必须在这里解决两种复杂性。对于一个大小为 n 的数组，我们首先需要将数组分成两半，然后合并它们以获得一个大小为 n 的数组。这可以用`T(n)`来表示：

```php
T(n)     = T(n/2) + T(n/2) + n    , for N>1 with T(1) = 0 

         = 2 T(n/2)+n 

T(n)/n   = 2 T(n/2)/n + 1              // divide both side by n 

         = T(n/2)/(n/2)  + 1                  

         = T(n/4)/(n/4)  + 1+ 1        // telescoping 

         = T(n/8)/(n/8)  + 1+ 1 + 1      // again telescoping 

         = ...... 

         = T(n/n)/(n/n)  + 1 + 1 + 1 + ....... + 1 

         = log (n)                     // since T(1) = 0      

So T(n)  = n log (n)                   // multiply both side with n 

```

因此，归并排序的复杂度是`O(n log(n))`。以下是归并排序的复杂度图表：

| 最佳时间复杂度 | `Ω(nlog(n))` |
| --- | --- |
| 最坏时间复杂度 | `O(nlog(n))` |
| 平均时间复杂度 | `Θ(nlog(n))` |
| 空间复杂度（最坏情况） | `O(n)` |

# 理解快速排序

快速排序是另一种应用分而治之方法的高效排序算法。虽然它不像归并排序那样均等地分割，但它创建动态分区来对数据进行排序。这就是快速排序的工作原理：

1.  从数组中选择一个随机值，我们称之为枢轴。

1.  重新排列数组，使小于枢轴的项目移到它的左边，大于或等于枢轴的项目移到它的右边。这就是分区。

1.  递归调用*步骤 1*和*步骤 2*来解决两个子数组（枢轴的左边和右边）的问题，直到所有项目都排序完成。

从数组中选择一个枢轴的方法有很多种。我们可以选择数组的最左边的项目或最右边的项目。在这两种情况下，如果数组已经排序，它将达到最坏情况的复杂度。选择一个好的枢轴可以提高算法的效率。有一些不同的分区方法。我们将解释*Hoare Partition*，它比其他分区方法进行了更少的交换。以下是我们的快速排序的伪算法。我们将进行原地排序，因此不需要额外的空间：

```php
procedure Quicksort(A : array,p :int ,r: int)

    if (p < r)

       q = Partition(A,p,r)

       Quicksort(A,p,q)

       Quicksort(A,q+1,r)

    end if

end procedure

procedure Partition(A : array,p :int ,r: int)

    pivot = A[p]

    i = p-1

    j = r+1

    while (true)

           do

            i := i + 1

           while A[i] < pivot    

           do

             j := j - 1

           while A[j] > pivot

      if i < j then

          swap A[i] with A[j]

      else

          return j

      end if

   end while

end procedure

```

我们使用第一个项目作为枢轴元素。我们也可以选择最后一个项目或取中值来选择枢轴元素。现在让我们使用 PHP 来实现算法。

# 实现快速排序

如伪代码所示，我们将有两个函数来实现快速排序：一个函数用于执行快速排序本身，另一个用于分区。以下是执行快速排序的实现：

```php
function quickSort(array &$arr, int $p, int $r) {

  if($p < $r) {

    $q = partition($arr, $p, $r);

    quickSort($arr, $p, $q);

    quickSort($arr, $q+1, $r);

  }

}

```

以下是执行分区的实现：

```php
function partition(array &$arr, int $p, int $r){ 

  $pivot = $arr[$p]; 

  $i = $p-1; 

  $j = $r+1; 

  while(true) 

  { 

   do { 

    $i++; 

   } while($arr[$i] < $pivot && $arr[$i] != $pivot); 

   do { 

    $j--; 

   } while($arr[$j] > $pivot && $arr[$j] != $pivot); 

   if($i < $j) { 

    $temp = $arr[$i]; 

    $arr[$i] = $arr[$j]; 

    $arr[$j] = $temp; 

   } else { 

    return $j; 

      } 

  } 

}

 $arr = [20, 45, 93, 67, 10, 97, 52, 88, 33, 92]; 

quickSort($arr, 0, count($arr)-1); 

echo implode(",", $arr);

```

如果我们在分区中直观地说明枢轴和排序，我们可以看到以下图像。为简单起见，我们只显示了发生交换的步骤：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00062.gif)

# 快速排序的复杂性

快速排序的最坏情况复杂度可能与冒泡排序的复杂度相似。实际上是由于枢轴的选择导致的。以下是快速排序的复杂性图表：

| 最佳时间复杂度 | `Ω(nlog(n))` |
| --- | --- |
| 最坏时间复杂度 | `O(n²)` |
| 平均时间复杂度 | `Θ(nlog(n))` |
| 空间复杂度（最坏情况） | `O(log(n))` |

# 理解桶排序

桶排序也被称为箱排序。桶排序是一种分布排序系统，其中数组元素被放置在不同的桶中。然后每个桶都单独排序，可以使用另一个排序算法，或者应用递归桶排序。使用 PHP 实现桶排序可能如下所示：

```php
function bucketSort(array &$data) { 

    $n = count($data); 

    if ($n <= 0) 

         return;                          

    $min = min($data); 

    $max = max($data); 

    $bucket = []; 

    $bLen = $max - $min + 1; 

    $bucket = array_fill(0, $bLen, []); 

    for ($i = 0; $i < $n; $i++) { 

         array_push($bucket[$data[$i] - $min], $data[$i]); 

    } 

    $k = 0; 

    for ($i = 0; $i < $bLen; $i++) {

         $bCount = count($bucket[$i]);

      for ($j = 0; $j < $bCount; $j++) { 

          $data[$k] = $bucket[$i][$j];

          $k++;

      }

    }

} 

```

桶排序的时间复杂度比其他基于比较的排序算法要好。以下是桶排序的复杂性：

| 最佳时间复杂度 | `Ω(n+k)` |
| --- | --- |
| 最坏时间复杂度 | `O(n²)` |
| 平均时间复杂度 | `Θ(n+k)` |
| 空间复杂度（最坏情况） | `O(n)` |

# 使用 PHP 的内置排序函数

PHP 具有丰富的预定义函数库，其中还包括不同的排序函数。它有不同的函数来按值或按键/索引对数组中的项目进行排序。在进行排序时，我们还可以保持数组值与其相应键的关联。PHP 的另一个重要函数是用于对多维数组进行排序的内置函数。以下是这些函数的摘要：

| **函数名称** | **目的** |
| --- | --- |
| `sort()` | 这将按升序对数组进行排序。不保留值/键关联。 |
| `rsort()` | 按照逆序/降序对数组进行排序。不保留索引/键关联。 |
| `asort()` | 在保持索引关联的同时对数组进行排序。 |
| `arsort()` | 以逆序排序数组并保持索引关联。 |
| `ksort()` | 按键对数组进行排序。它保持键与数据的关联。这主要适用于关联数组。 |
| `krsort()` | 按键以逆序排序数组。 |
| `natsort()` | 使用自然顺序算法对数组进行排序，并保持值/键关联。 |
| `natcasesort()` | 使用不区分大小写的“自然顺序”算法对数组进行排序，并保持值/键关联。 |

| `usort()` | 使用用户定义的比较函数按值对数组进行排序，并且不保持值/键关联。

第二个参数是一个可调用的比较函数。 |

| `uksort()` | 使用用户定义的比较函数按键对数组进行排序，并保持值/键关联。

第二个参数是一个可调用的比较函数。 |

| `uasort()` | 使用用户定义的比较函数按值对数组进行排序，并保持值/键关联。

第二个参数是一个可调用的比较函数。 |

对于`sort`，`rsort`，`ksort`，`krsort`，`asort`和`arsort`，可以使用以下排序标志：

+   **SORT_REGULAR**：按原样比较项目（不更改类型）

+   **SORT_NUMERIC**：按数字比较项目

+   **SORT_STRING**：将项目作为字符串进行比较

+   **SORT_LOCALE_STRING**：根据当前区域设置将项目作为字符串进行比较

+   **SORT_NATURAL**：使用“自然顺序”将项目比较为字符串

# 摘要

在本章中，您了解了不同的排序算法。排序是我们开发过程中的一个重要部分，了解不同的排序算法及其复杂性将帮助我们根据问题集选择最佳的排序算法。还有其他排序算法，可以在网上找到进行进一步研究。我们故意没有在本章中涵盖堆排序，因为我们将在*第十章*中讨论。在下一章中，我们将讨论另一个关于算法的重要主题 - 搜索。


# 第八章：探索搜索选项

除了排序，搜索是编程世界中最常用的算法之一。无论是搜索电话簿、电子邮件、数据库还是文件，我们实际上都在执行某种搜索技术来定位我们希望找到的项目。搜索和排序是编程中最重要的两个组成部分。在本章中，您将学习不同的搜索技术以及它们的效率。我们还将学习有关搜索树数据结构的不同搜索方式。

# 线性搜索

执行搜索的最常见方式之一是将每个项目与我们要查找的项目进行比较。这被称为线性搜索或顺序搜索。这是执行搜索的最基本方式。如果我们考虑列表中有*n*个项目，在最坏的情况下，我们必须搜索*n*个项目才能找到特定的项目。我们可以遍历列表或数组来查找项目。让我们考虑以下例子：

```php
function search(array $numbers, int $needle): bool {

    $totalItems = count($numbers);

    for ($i = 0; $i < $totalItems; $i++) {

      if($numbers[$i] === $needle){

        return TRUE;

      }

     }

    return FALSE;

}

```

我们有一个名为`search`的函数，它接受两个参数。一个是数字列表，另一个是我们要在列表中查找的数字。我们运行一个 for 循环来遍历列表中的每个项目，并将它们与我们的项目进行比较。如果找到匹配项，我们返回 true 并且不继续搜索。然而，如果循环结束并且没有找到任何东西，我们在函数定义的末尾返回 false。让我们使用`search`函数来使用以下程序查找一些东西：

```php
$numbers = range(1, 200, 5); 

if (search($numbers, 31)) { 

    echo "Found"; 

} else { 

    echo "Not found"; 

}

```

在这里，我们使用 PHP 的内置函数 range 生成一个随机数组，范围是 1 到 200。每个项目的间隔为 5，如 1、6、11、16 等；然后我们搜索 31，在列表中有 6、11、16、21、26、31 等。然而，如果我们要搜索 32 或 33，那么项目将找不到。因此，对于这种情况，我们的输出将是`Found`。

我们需要记住的一件事是，我们不必担心我们的列表是否按任何特定顺序或特定方式组织。如果我们要查找的项目在第一个位置，那将是最好的结果。最坏的结果可能是最后一个项目或不在列表中的项目。在这两种情况下，我们都必须遍历列表的所有*n*个项目。以下是线性/顺序搜索的复杂性：

| 最佳时间复杂度 | `O(1)` |
| --- | --- |
| 最坏时间复杂度 | `O(n)` |
| 平均时间复杂度 | `O(n)` |
| 空间复杂度（最坏情况） | `O(1)` |

正如我们所看到的，线性搜索的平均或最坏时间复杂度为`O(n)`，这并不会改变我们对项目列表的排序方式。现在，如果数组中的项目按特定顺序排序，那么我们可能不必进行线性搜索，而可以通过选择性或计算性搜索获得更好的结果。最流行和知名的搜索算法是"二分搜索"。是的，这听起来像你在第六章中学到的二分搜索树，*理解和实现树*，但我们甚至可以在不构建二分搜索树的情况下使用这个算法。所以，让我们来探索一下。

# 二分搜索

二分搜索是编程世界中非常流行的搜索算法。在顺序搜索中，我们从开头开始扫描每个项目以找到所需的项目。然而，如果列表已经排序，那么我们就不需要从列表的开头或结尾开始搜索。在二分搜索算法中，我们从列表的中间开始，检查中间的项目是比我们要找的项目小还是大，并决定要走哪条路。这样，我们将列表分成两半，并丢弃一半，就像下面的图片一样：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00063.jpg)

如果我们看前面的图片，我们有一个按升序排序的数字列表。我们想知道项目**7**是否在数组中。由于数组有 17 个项目（0 到 16 索引），我们将首先转到中间索引，对于这个示例来说是第八个索引。现在，第八个索引的值为**14**，大于我们要搜索的值**7**。这意味着如果**7**在这个数组中，它在**14**的左边，因为数字已经排序。因此，我们放弃了从第八个索引到第十六个索引的数组，因为数字不能在数组的那一部分。现在，我们重复相同的过程，并取数组剩余部分的中间部分，即剩余部分的第三个元素。现在，第三个元素的值为**6**，小于**7**。因此，我们要找的项目在剩余部分的第三个元素的右侧，而不是左侧。

现在，我们将检查数组的第四个元素到第七个元素，中间元素现在指向第五个元素。第五个元素的值为**8**，大于**7**，我们要找的值。因此，我们必须考虑第五个元素的左侧来找到我们要找的项目。这次，我们只剩下两个项目要检查，即第四个和第五个元素。当我们向左移动时，我们将检查第四个元素，我们看到值与我们要找的**7**匹配。如果第四个索引值不是**7**，函数将返回 false，因为没有更多的元素可以检查。如果我们看一下前面图片中的箭头标记，我们可以看到在四步内，我们已经找到了我们要找的值，而在线性搜索函数中，我们需要花 17 步来检查所有 17 个数字，这是最坏情况下的二分搜索，或半间隔搜索，或对数搜索。

正如我们在上一张图片中看到的，我们必须将初始列表分成两半，并继续直到达到一个不能再进一步分割以找到我们的项目的地步。我们可以使用迭代方式或递归方式来执行分割部分。我们将实际上使用两种方式。因此，让我们首先定义迭代方式中的二分搜索的伪代码：

```php
BinarySearch(A : list of sorted items, value) { 

       low = 0 

       high = N

       while (low <= high) { 

    // lowest int value, no fraction 

           mid = (low + high) / 2              

           if (A[mid] > value) 

               high = mid - 1 

           else if (A[mid] < value) 

               low = mid + 1 

           else  

             return true 

       }

       return false 

 }

```

如果我们看一下伪代码，我们可以看到我们根据中间值调整了低和高。如果我们要查找的值大于中间值，我们将调整下界为`mid+1`。如果小于中间值，则将上界设置为`mid-1`。直到下界变大于上界或找到项目为止。如果未找到项目，我们在函数末尾返回 false。现在，让我们使用 PHP 实现伪代码：

```php
function binarySearch(array $numbers, int $needle): bool { 

    $low = 0; 

    $high = count($numbers) - 1; 

    while ($low <= $high) { 

      $mid = (int) (($low + $high) / 2); 

      if ($numbers[$mid] > $needle) { 

          $high = $mid - 1;

      } else if ($numbers[$mid] < $needle) { 

          $low = $mid + 1;

      } else {

          return TRUE;

      }

    }

    return FALSE; 

}

```

在我们的实现中，我们遵循了前一页中的大部分伪代码。现在，让我们运行两次搜索的代码，我们知道一个值在列表中，一个值不在列表中：

```php
$numbers = range(1, 200, 5); 

$number = 31;

if (binarySearch($numbers, $number) !== FALSE) { 

    echo "$number Found \n"; 

} else { 

    echo "$number Not found \n"; 

} 

$number = 500; 

if (binarySearch($numbers, $number) !== FALSE) { 

    echo "$number Found \n"; 

} else { 

    echo "$number Not found \n"; 

} 

```

根据我们之前的线性搜索代码，`31`在列表中，应该显示`Found`。然而，`500`不在列表中，应该显示`Not found`。如果我们运行代码，这是我们在控制台中看到的输出：

```php
31 Found

500 Not found

```

我们现在将为二分搜索编写递归算法，这对我们也很方便。伪代码将要求我们在每次调用函数时发送额外的参数。我们需要在每次递归调用时发送低和高，这是迭代调用中没有做的：

```php
BinarySearch(A : list of sorted items, value, low, high) { 

   if (high < low) 

          return false 

      // lowest int value, no fraction 

           mid = (low + high) / 2   

           if (A[mid] > value) 

               return BinarySearch(A, value, low, mid - 1) 

           else if (A[mid] < value) 

               return BinarySearch(A, value, mid + 1, high)  

     else 

      return TRUE;      

}

```

从前面的伪代码中我们可以看到，现在我们有低和高作为参数，在每次调用中，新值作为参数发送。我们有边界条件，检查低是否大于高。与迭代的代码相比，代码看起来更小更干净。现在，让我们使用 PHP 7 来实现这个：

```php
function binarySearch(array $numbers, int $needle,  

int $low, int $high): bool { 

    if ($high < $low) { 

    return FALSE; 

    } 

    $mid = (int) (($low + $high) / 2); 

    if ($numbers[$mid] > $needle) { 

      return binarySearch($numbers, $needle, $low, $mid - 1); 

    } else if ($numbers[$mid] < $needle) { 

      return binarySearch($numbers, $needle, $mid + 1, $high); 

    } else { 

      return TRUE; 

    } 

}

```

现在，让我们使用以下代码来递归运行这个搜索：

```php
$numbers = range(1, 200, 5); 

$number = 31; 

if (binarySearch($numbers, $number, 0, count($numbers) - 1) !== FALSE) { 

    echo "$number Found \n"; 

} else { 

    echo "$number Not found \n"; 

} 

$number = 500; 

if (binarySearch($numbers, $number, 0, count($numbers) - 1) !== FALSE) { 

    echo "$number Found \n"; 

} else { 

    echo "$number Not found \n"; 

}

```

正如我们从前面的代码中看到的，我们在递归二分搜索的每次调用中发送`0`和`count($numbers)-1`。然后，这个高和低在每次递归调用时根据中间值自动调整。因此，我们已经看到了二分搜索的迭代和递归实现。根据我们的需求，我们可以在程序中使用其中一个。现在，让我们分析二分搜索算法，并找出它为什么比我们的线性或顺序搜索算法更好。

# 二分搜索算法的分析

到目前为止，我们已经看到，对于每次迭代，我们都将列表分成一半，并丢弃一半进行搜索。这使得我们的列表在 1、2 和 3 次迭代后看起来像*n/2*、*n/4*、*n/8*，依此类推。因此，我们可以说，在第 K 次迭代后，将剩下*n/2^k*个项目。我们可以轻松地说，最后一次迭代发生在*n/2^k = 1*时，或者我们可以说，*2^K = n*。因此，从两边取对数得到，*k = log(n)*，这是二分搜索算法的最坏情况运行时间。以下是二分搜索算法的复杂性：

| 最佳时间复杂度 | `O(1)` |
| --- | --- |
| 最坏时间复杂度 | `O(log n)` |
| 平均时间复杂度 | `O(log n)` |
| 空间复杂度（最坏情况） | `O(1)` |

如果我们的数组或列表已经排序，总是更倾向于应用二分搜索以获得更好的性能。现在，无论列表是按升序还是降序排序，都会对我们计算的低和高产生一些影响。到目前为止，我们看到的逻辑是针对升序的。如果数组按降序排序，逻辑将被交换，大于将变成小于，反之亦然。这里需要注意的一点是，二分搜索算法为我们提供了搜索项的索引。然而，可能有一些情况，我们不仅需要知道数字是否存在，还需要找到列表中的第一次出现或最后一次出现。如果我们使用二分搜索算法，它将返回 true 或最大索引号，搜索算法找到数字的地方。然而，这可能不是第一次出现或最后一次出现。为此，我们将稍微修改二分搜索算法，称之为重复二叉搜索树算法。

# 重复二叉搜索树算法

考虑以下图片。我们有一个包含重复项的数组。如果我们尝试从数组中找到**2**的第一次出现，上一节的二分搜索算法将给我们第五个元素。然而，从下面的图片中，我们可以清楚地看到它不是第五个元素；相反，它是第二个元素，这才是正确的答案。因此，我们需要对我们的二分搜索算法进行修改。修改将是重复搜索，直到我们找到第一次出现：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00064.gif)

这是使用迭代方法的修改后的解决方案：

```php
function repetitiveBinarySearch(array $numbers, int $needle): int { 

    $low = 0;

    $high = count($numbers) - 1;

    $firstOccurrence = -1;

    while ($low <= $high) { 

      $mid = (int) (($low + $high) / 2); 

      if ($numbers[$mid] === $needle) { 

          $firstOccurrence = $mid; 

          $high = $mid - 1; 

      } else if ($numbers[$mid] > $needle) { 

          $high = $mid - 1;

      } else {

          $low = $mid + 1;

      } 

    } 

    return $firstOccurrence; 

} 

```

正如我们所看到的，首先我们要检查中间值是否是我们要找的值。如果是真的，那么我们将中间索引分配为第一次出现，并且我们将搜索中间元素的左侧以检查我们要找的数字的任何出现。然后我们继续迭代，直到我们搜索了每个索引（`$low`大于`$high`）。如果没有找到进一步的出现，那么第一次出现的变量将具有我们找到该项的第一个索引的值。如果没有，我们像往常一样返回`-1`。让我们运行以下代码来检查我们的结果是否正确：

```php
$numbers = [1, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 4, 4, 5, 5]; 

$number = 2; 

$pos = repetitiveBinarySearch($numbers, $number); 

if ($pos >= 0) { 

    echo "$number Found at position $pos \n"; 

} else { 

    echo "$number Not found \n"; 

} 

$number = 5; 

$pos = repetitiveBinarySearch($numbers, $number); 

if ($pos >= 0) { 

    echo "$number Found at position $pos \n"; 

} else { 

    echo "$number Not found \n"; 

}

```

现在，我们有一个包含重复值的数组，值为 2、3、4 和 5。我们想搜索数组，并找到值第一次出现的位置或索引。例如，如果我们在一个常规的二分搜索函数中搜索 `2`，它会返回第八个位置，即它找到值 `2` 的位置。在我们的情况下，我们实际上是在寻找第二个索引，它实际上保存了项目 `2` 的第一次出现。我们的函数 `repetitiveBinarySearch` 正是这样做的，我们将返回的位置存储到一个名为 `$pos` 的变量中。如果找到数字，我们将显示输出以及位置。现在，如果我们在控制台中运行前面的代码，我们将得到以下输出：

```php
2 Found at position 1

5 Found at position 16

```

这符合我们的预期结果。因此，我们现在有了一个重复的二分搜索算法，用于查找给定排序列表中项目的第一次和最后一次出现。这可能是一个非常方便的函数来解决许多问题。

到目前为止，从我们的例子和分析来看，我们可以得出结论，二分搜索肯定比线性搜索更快。然而，主要的前提是在应用二分搜索之前对列表进行排序。在未排序的数组中应用二分搜索会导致我们得到不准确的结果。有时候我们会收到一个数组，而我们不确定这个数组是否已经排序。现在，问题是，“在这种情况下，我们应该先对数组进行排序然后应用二分搜索算法吗？还是应该只运行线性搜索算法来找到一个项目？”让我们讨论一下这个问题，这样我们就知道如何处理这种情况。

# 搜索一个未排序的数组 - 我们应该先排序吗？

所以现在，我们处于这样一种情况：我们有一个包含 *n* 个项目的数组，它们没有排序。由于我们知道二分搜索更快，我们决定先对其进行排序，然后使用二分搜索来搜索项目。如果我们这样做，我们必须记住，最好的排序算法的最坏时间复杂度为 `O(nlog n)`，而对于二分搜索，最坏情况的复杂度为 `O(log n)`。因此，如果我们先排序然后应用二分搜索，复杂度将为 `O(n log n)`，因为这是与 `O(log n)` 相比最大的。然而，我们也知道，对于任何线性或顺序搜索（无论是排序还是未排序），最坏的时间复杂度都是 `O(n)`，这比 `O(n log n)` 要好得多。根据 `O(n)` 和 `O(n log n)` 的复杂度比较，我们可以清楚地说，如果数组没有排序，执行线性搜索是一个更好的选择。

让我们考虑另一种情况，我们需要多次搜索一个给定的数组。让我们用 *k* 表示我们想要搜索数组的次数。如果 *k* 为 1，那么我们可以轻松地应用上一段讨论的线性方法。如果 *k* 的值相对于数组的大小 *n* 来说比较小，那么也没问题。然而，如果 *k* 的值接近或大于 *n*，那么我们在这里应用线性方法就会有一些问题。

假设 *k = n*，那么对于 *n* 次搜索，线性搜索的复杂度将为 `O(n²)`。现在，如果我们选择排序然后搜索，即使 *k* 更大，一次排序也只需要 `O(n log n)` 的时间复杂度。然后，每次搜索只需要 `O(log n)`，而 *n* 次搜索的最坏情况复杂度为 `O(n log n)`。如果我们在这里考虑最坏的情况，那么对于排序和搜索 *k* 个项目，我们将得到 `O(n log n)`，这比顺序搜索要好。

因此，我们可以得出结论：如果搜索操作的次数较小，与数组的大小相比，最好不要对数组进行排序，而是执行顺序搜索。然而，如果搜索操作的次数较大，与数组的大小相比，最好先对数组进行排序，然后应用二分搜索。

多年来，二分搜索算法不断发展，并出现了不同的变体。我们可以通过计算决策来选择下一个应该使用的索引，而不是每次选择中间索引。这就是这些变体能够高效工作的原因。现在我们将讨论二分搜索算法的两种变体：插值搜索和指数搜索。

# 插值搜索

在二分搜索算法中，我们总是从数组的中间开始搜索过程。如果数组是均匀分布的，并且我们正在寻找一个可能接近数组末尾的项目，那么从中间开始搜索可能对我们来说并不是一个好选择。在这种情况下，插值搜索可能非常有帮助。插值搜索是对二分搜索算法的改进。插值搜索可能根据搜索关键字的值而转到不同的位置。例如，如果我们正在搜索一个接近数组开头的关键字，它将转到数组的第一部分，而不是从中间开始。位置是使用探测位置计算器方程计算的，如下所示：

```php
pos = low + [ (key-arr[low])*(high-low) / (arr[high]-arr[low]) ]

```

正如我们所看到的，我们从通用的 `mid = (low+high)/2` 方程转变为一个更复杂的方程。如果搜索的关键字更接近 `arr[high]`，这个公式将返回一个更高的值，如果关键字更接近 `arr[low]`，则返回一个更低的值。现在，让我们借助我们的二分搜索代码来实现这种搜索方法：

```php
function interpolationSearch(array $arr, int $key): int { 

    $low = 0; 

    $high = count($arr) - 1; 

    while ($arr[$high] != $arr[$low] && $key >= $arr[$low] && 

      $key <= $arr[$high]) { 

    $mid = intval($low + (($key - $arr[$low]) * ($high - $low) 

    / ($arr[$high] - $arr[$low]))); 

      if ($arr[$mid] < $key) 

          $low = $mid + 1; 

      else if ($key < $arr[$mid]) 

          $high = $mid - 1; 

      else 

          return $mid; 

    } 

    if ($key == $arr[$low]) 

      return $low; 

    else

      return -1; 

}

```

在这里，我们以一种不同的方式进行计算。尽管它需要更多的计算步骤，但好处是，如果列表是均匀分布的，那么该算法的平均复杂度为 `O(log (log n))`，这与二分搜索的复杂度 `O(log n)` 相比要好得多。此外，我们必须小心，如果关键字的分布不均匀，插值搜索的性能可能会下降。

现在，我们将探讨另一种二分搜索的变体，称为指数搜索，它可以改进算法。

# 指数搜索

在二分搜索中，我们为给定的关键字搜索整个列表。指数搜索通过决定搜索的下限和上限来改进二分搜索，以便我们不会最终搜索整个列表。它改进了我们需要找到一个元素所需的比较次数。搜索分为以下两个步骤：

1.  我们通过寻找第一个指数 *k*，其中 *2^k* 的值大于搜索项，来确定边界大小。现在，*2^k* 和 *2^(k-1)* 分别成为上限和下限。

1.  对 *2^k* 和 *2^(k-1)* 进行二分搜索算法。

现在让我们使用我们的递归 `binarySearch` 函数来实现指数搜索：

```php
function exponentialSearch(array $arr, int $key): int { 

    $size = count($arr); 

    if ($size == 0) 

      return -1; 

    $bound = 1; 

    while ($bound < $size && $arr[$bound] < $key) { 

      $bound *= 2; 

    } 

    return binarySearch($arr, $key, intval($bound / 2),  

min($bound, $size)); 

}

```

在第一步中，我们需要 *i* 步来确定边界。因此，该算法的复杂度为 `O(log i)`。我们必须记住，这里的 *i* 要远小于 *n*。然后，我们使用 *2^j* 到 *2^(j-1)* 进行二分搜索，其中 *j = log i*。我们知道二分搜索的复杂度为 `O(log n)`，其中 *n* 是列表的大小。然而，由于我们正在进行较小范围的搜索，实际上我们搜索的是 *2 ^(log i) \ - 2 ^(log i) - 1 = 2 ^(log i - 1)* 大小。因此，这个边界的复杂度将是 log *(2 ^(log i - 1) ) = log (i) - 1 = O(log i)*。

因此，指数搜索的复杂性如下：

| 最佳时间复杂度 | `O(1)` |
| --- | --- |
| 最坏时间复杂度 | `O(log i)` |
| 平均时间复杂度 | `O(log i)` |
| 空间复杂度（最坏情况） | `O(1)` |

# 使用哈希表进行搜索

哈希表在搜索操作时可以是非常高效的数据结构。由于哈希表以关联方式存储数据，如果我们知道在哪里查找数据，我们可以很容易地快速获取数据。在哈希表中，每个数据都有一个与之关联的唯一索引。如果我们知道要查看哪个索引，我们可以很容易地找到键。通常，在其他编程语言中，我们必须使用单独的哈希函数来计算哈希索引以存储值。哈希函数旨在为相同的键生成相同的索引，并避免冲突。然而，PHP 的一个伟大特性是 PHP 数组本身就是一个哈希表，在其底层 C 实现中。由于数组是动态的，我们不必担心数组的大小或溢出数组的值。我们需要将值存储在关联数组中，以便我们可以将值与键关联起来。如果是字符串或整数，键可以是值本身。让我们运行一个例子来理解使用哈希表进行搜索：

```php
$arr = [];

$count = rand(10, 30); 

for($i = 0; $i<$count;$i++) {     

    $val = rand(1,500);     

    $arr[$val] = $val;     

} 

$number = 100; 

if(isset($arr[$number])) { 

    echo "$number found "; 

} else { 

    echo "$number not found"; 

}

```

我们刚刚构建了一个简单的随机关联数组，其中值和键是相同的。由于我们使用的是 PHP 数组，尽管值可以在 1 到 500 的范围内，实际数组大小可以是 10 到 30 之间的任何值。如果是在其他语言中，我们将构建一个大小为 501 的数组来容纳这个值作为键。这就是为什么要使用哈希函数来计算索引。如果需要的话，我们也可以使用 PHP 的内置哈希函数：

```php
string hash(string $algo ,string $data [,bool $raw_output = false ])

```

第一个参数采用我们想要用于哈希的算法类型。我们可以选择 md5、sha1、sha256、crc32 等。每个算法都会产生一个固定长度的哈希输出，我们可以将其用作哈希表的键。

如果我们看一下我们的搜索部分，我们可以看到我们实际上是直接检查相关的索引。这使得我们的搜索复杂度为`O(1)`。在 PHP 中，使用哈希表进行快速搜索可能是有益的，即使不使用哈希函数。但是，如果需要的话，我们总是可以使用哈希函数。

到目前为止，我们已经涵盖了基于数组和线性结构的搜索。现在我们将把重点转移到层次化数据结构搜索，比如搜索树和图。虽然我们还没有讨论图（我们将在下一章讨论），但我们将把重点放在树搜索上，这也可以应用于图搜索。

# 树搜索

搜索层次化数据的最佳方法之一是创建搜索树。在第六章中，*理解和实现树*，我们看到了如何构建二叉搜索树并提高搜索效率。我们还发现了遍历树的不同方法。现在，我们将探索两种最流行的搜索树结构的方式，通常称为广度优先搜索（BFS）和深度优先搜索（DFS）。

# 广度优先搜索

在树结构中，根节点连接到其子节点，每个子节点都可以表示为一棵树。我们在第六章中已经看到了这一点，*理解和实现树*。在广度优先搜索中，通常称为 BFS，我们从一个节点（通常是根节点）开始，首先访问所有相邻或邻居节点，然后再访问其他邻居节点。换句话说，我们必须逐层移动，而我们应用 BFS。由于我们逐层搜索，这种技术被称为广度优先搜索。在下面的树结构中，我们可以使用 BFS：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00065.jpg)

对于这棵树，BFS 将按照以下节点进行：![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00066.jpg)

BFS 的伪代码如下：

```php
procedure BFS(Node root)  

  Q := empty queue 

  Q.enqueue(root); 

  while(Q != empty) 

     u := Q.dequeue() 

     for each node w that is childnode of u 

        Q.enqueue(w) 

     end for each 

  end while 

end procedure

```

我们可以看到我们保留了一个队列来跟踪我们需要访问的节点。我们可以保留另一个队列来保存访问的顺序，并将其返回以显示访问顺序。现在，我们将使用 PHP 7 来实现 BFS。

# 实现广度优先搜索

到目前为止，我们还没有详细介绍图，因此我们将严格将 BFS 和 DFS 的实现保留在树结构中。此外，我们将使用我们在第六章中看到的通用树结构，*理解和实现树*，（甚至不是二叉树）。我们将使用相同的`TreeNode`类来定义我们的节点和与子节点的关系。因此，现在让我们定义具有 BFS 功能的`Tree`类：

```php
class TreeNode { 

    public $data = NULL; 

    public $children = []; 

    public function __construct(string $data = NULL) { 

      $this->data = $data; 

    } 

    public function addChildren(TreeNode $node) { 

      $this->children[] = $node; 

    } 

} 

class Tree { 

    public $root = NULL; 

    public function __construct(TreeNode $node) { 

      $this->root = $node; 

    } 

    public function BFS(TreeNode $node): SplQueue { 

      $queue = new SplQueue; 

      $visited = new SplQueue; 

      $queue->enqueue($node); 

      while (!$queue->isEmpty()) { 

          $current = $queue->dequeue(); 

          $visited->enqueue($current); 

          foreach ($current->children as $child) { 

            $queue->enqueue($child); 

          } 

      } 

    return $visited; 

    }

}

```

我们在树类内部实现了 BFS 方法。我们以根节点作为广度优先搜索的起点。在这里，我们有两个队列：一个用于保存我们需要访问的节点，另一个用于我们已经访问的节点。我们还在方法的最后返回了访问的队列。现在让我们模仿一下我们在本节开头看到的树。我们想要像图中显示的树一样放置数据，并检查 BFS 是否实际返回我们期望的模式：![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00066.jpg)：

```php
    $root = new TreeNode("8"); 

    $tree = new Tree($root); 

    $node1 = new TreeNode("3"); 

    $node2 = new TreeNode("10"); 

    $root->addChildren($node1); 

    $root->addChildren($node2); 

    $node3 = new TreeNode("1"); 

    $node4 = new TreeNode("6"); 

    $node5 = new TreeNode("14"); 

    $node1->addChildren($node3); 

    $node1->addChildren($node4); 

    $node2->addChildren($node5); 

    $node6 = new TreeNode("4"); 

    $node7 = new TreeNode("7"); 

    $node8 = new TreeNode("13"); 

    $node4->addChildren($node6); 

    $node4->addChildren($node7); 

    $node5->addChildren($node8); 

    $visited = $tree->BFS($tree->root); 

    while (!$visited->isEmpty()) { 

      echo $visited->dequeue()->data . "\n"; 

    } 

```

我们在这里通过创建节点并将它们附加到根和其他节点来构建整个树结构。一旦树完成，我们就调用`BFS`方法来找到遍历的完整序列。最后的`while`循环打印了我们访问的节点序列。以下是前面代码的输出：

```php
8

3

10

1

6

14

4

7

13

```

我们已经收到了我们期望的结果。现在，如果我们想搜索以查找节点是否存在，我们可以为我们的`$current`节点值添加一个简单的条件检查。如果匹配，那么我们可以返回访问的队列。

BFS 的最坏复杂度为**O**(*|V| + |E*),其中*V*是顶点或节点的数量，*E*是节点之间的边或连接的数量。对于空间复杂度，最坏情况是**O**(*|V|*)。

图的 BFS 类似，但有一点不同。由于图可能是循环的（可以创建循环），我们需要确保我们不会一遍又一遍地访问相同的节点以创建无限循环。为了避免重新访问图节点，我们必须跟踪我们已经访问的节点。为了标记已访问的节点，我们可以使用队列，或使用图着色算法。我们将在下一章中探讨这一点。

# 深度优先搜索

深度优先搜索，或 DFS，是一种搜索技术，我们从一个节点开始搜索，并尽可能深入到目标节点通过分支。DFS 不同于 BFS，我们尝试更深入地挖掘而不是首先扩散。DFS 垂直增长，并在到达分支的末端时回溯，并移动到下一个可用的相邻节点，直到搜索结束。我们可以从上一节中取相同的树图像，如下所示：

![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00067.jpg)

如果我们在这里应用 DFS，遍历将是![](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php7-dsal/img/Image00068.jpg)。我们从根开始，然后访问第一个子节点，即**3**。然而，与 BFS 不同，我们将探索**3**的子节点，并重复此过程，直到达到分支的底部。在 BFS 中，我们采用了迭代方法。对于 DFS，我们将采用递归方法。现在让我们为 DFS 编写伪代码：

```php
procedure DFS(Node current)       

     for each node v that is childnode of current  

        DFS(v) 

     end for each 

end procedure 

```

# 实现深度优先搜索

DFS 的伪代码看起来很简单。为了跟踪节点访问的顺序，我们需要使用一个队列，它将跟踪我们`Tree`类内部的节点。以下是我们带有递归 DFS 的`Tree`类的实现：

```php
class TreeNode { 

    public $data = NULL; 

    public $children = []; 

    public function __construct(string $data = NULL) { 

      $this->data = $data; 

    } 

    public function addChildren(TreeNode $node) { 

      $this->children[] = $node; 

    } 

} 

class Tree { 

    public $root = NULL; 

    public $visited; 

    public function __construct(TreeNode $node) { 

      $this->root = $node; 

      $this->visited = new SplQueue; 

    } 

    public function DFS(TreeNode $node) { 

      $this->visited->enqueue($node); 

      if($node->children){ 

          foreach ($node->children as $child) { 

        $this->DFS($child); 

          } 

      } 

    }

}

```

正如我们所看到的，我们在树类中添加了一个额外的属性`$visited`来跟踪访问的节点。当我们调用`DFS`方法时，我们将节点添加到队列中。现在，如果我们使用上一节中的相同树结构，只需添加 DFS 调用并获取访问部分，它将如下所示：

```php
try { 

    $root = new TreeNode("8"); 

    $tree = new Tree($root); 

    $node1 = new TreeNode("3"); 

    $node2 = new TreeNode("10"); 

    $root->addChildren($node1); 

    $root->addChildren($node2); 

    $node3 = new TreeNode("1"); 

    $node4 = new TreeNode("6"); 

    $node5 = new TreeNode("14"); 

    $node1->addChildren($node3); 

    $node1->addChildren($node4); 

    $node2->addChildren($node5); 

    $node6 = new TreeNode("4"); 

    $node7 = new TreeNode("7"); 

    $node8 = new TreeNode("13"); 

    $node4->addChildren($node6); 

    $node4->addChildren($node7); 

    $node5->addChildren($node8); 

    $tree->DFS($tree->root); 

    $visited = $tree->visited; 

    while (!$visited->isEmpty()) { 

      echo $visited->dequeue()->data . "\n"; 

    } 

} catch (Exception $e) { 

    echo $e->getMessage(); 

}

```

由于 DFS 不返回任何内容，我们使用类属性`visited`来获取队列，以便我们可以显示访问节点的序列。如果我们在控制台中运行此程序，将会得到以下输出：

```php
8

3

1

6

4

7

10

14

13

```

结果符合预期。如果我们需要 DFS 的迭代解决方案，我们必须记住，我们需要使用堆栈而不是队列来跟踪下一个要访问的节点。然而，由于堆栈遵循 LIFO 原则，对于我们提到的图像，输出将与我们最初的想法不同。以下是使用迭代方法的实现：

```php
class TreeNode { 

    public $data = NULL; 

    public $children = []; 

    public function __construct(string $data = NULL) { 

      $this->data = $data; 

    } 

    public function addChildren(TreeNode $node) { 

      $this->children[] = $node; 

    } 

} 

class Tree { 

    public $root = NULL; 

    public function __construct(TreeNode $node) { 

      $this->root = $node; 

    }

    public function DFS(TreeNode $node): SplQueue { 

      $stack = new SplStack;

      $visited = new SplQueue;

      $stack->push($node);

      while (!$stack->isEmpty()) { 

          $current = $stack->pop(); 

          $visited->enqueue($current); 

          foreach ($current->children as $child) { 

            $stack->push($child); 

          } 

      } 

      return $visited; 

    }

}

try {

    $root = new TreeNode("8"); 

    $tree = new Tree($root); 

    $node1 = new TreeNode("3"); 

    $node2 = new TreeNode("10"); 

    $root->addChildren($node1); 

    $root->addChildren($node2); 

    $node3 = new TreeNode("1"); 

    $node4 = new TreeNode("6"); 

    $node5 = new TreeNode("14"); 

    $node1->addChildren($node3); 

    $node1->addChildren($node4); 

    $node2->addChildren($node5); 

    $node6 = new TreeNode("4"); 

    $node7 = new TreeNode("7"); 

    $node8 = new TreeNode("13"); 

    $node4->addChildren($node6); 

    $node4->addChildren($node7); 

    $node5->addChildren($node8); 

    $visited = $tree->DFS($tree->root); 

    while (!$visited->isEmpty()) { 

      echo $visited->dequeue()->data . "\n"; 

    } 

} catch (Exception $e) { 

    echo $e->getMessage(); 

}

```

它看起来与我们的迭代 BFS 算法非常相似。主要区别在于使用堆栈数据结构而不是队列数据结构来存储已访问的节点。这也会对输出产生影响。前面的代码将产生输出`8 → 10 → 14 → 13 → 3 → 6 → 7 → 4 → 1`。这与上一节中显示的先前输出不同。由于我们使用堆栈，输出实际上是正确的。我们使用堆栈来推入特定节点的子节点。对于我们的根节点，其值为**8**，我们有值为**3**的第一个子节点。它被推入堆栈，然后，根的第二个子节点的值为**10**，也被推入堆栈。由于值**10**是最后被推入的，它将首先出现，遵循堆栈的 LIFO 原则。因此，如果我们使用堆栈，顺序始终将从最后的分支开始到第一个分支。然而，如果我们想要保持节点的顺序从左到右，那么我们需要在 DFS 代码中进行一些小的调整。以下是带有更改的代码块：

```php
public function DFS(TreeNode $node): SplQueue { 

  $stack = new SplStack; 

  $visited = new SplQueue;

  $stack->push($node); 

  while (!$stack->isEmpty()) { 

      $current = $stack->pop(); 

      $visited->enqueue($current); 

      $current->children = array_reverse($current->children); 

      foreach ($current->children as $child) { 

        $stack->push($child); 

      } 

    } 

    return $visited;

}

```

与上一个代码块的唯一区别是，在访问特定节点的子节点之前，我们添加了以下行：

```php
$current->children = array_reverse($current->children);

```

由于堆栈执行后进先出（LIFO）的操作，通过反转，我们确保首先访问第一个节点，因为我们已经反转了顺序。实际上，它将简单地作为队列工作。这将产生 DFS 部分所示的期望顺序。如果我们有一棵二叉树，那么我们可以很容易地做到这一点，而不需要任何反转，因为我们可以选择先推入右子节点，然后再推入左子节点以先弹出左子节点。

DFS 的最坏复杂度为**O**（*|V| + |E|*），其中*V*是顶点或节点的数量，*E*是节点之间的边或连接的数量。对于空间复杂度，最坏情况是**O**（*|V|*），这与 BFS 类似。

# 摘要

在本章中，我们讨论了不同的搜索算法及其复杂性。您学会了如何通过哈希表来改进搜索，以获得恒定的时间结果。我们还探讨了 BFS 和 DFS，这两种是层次数据搜索中最重要的方法之一。我们将使用类似的概念来探索下一章中即将探讨的图数据结构。图算法对于解决许多问题至关重要，并且在编程世界中被广泛使用。让我们继续探讨另一个有趣的主题 - 图。
