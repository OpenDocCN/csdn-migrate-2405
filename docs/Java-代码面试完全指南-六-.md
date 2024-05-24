# Java 代码面试完全指南（六）

> 原文：[`zh.annas-archive.org/md5/2AD78A4D85DC7F13AC021B920EE60C36`](https://zh.annas-archive.org/md5/2AD78A4D85DC7F13AC021B920EE60C36)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十四章：排序和搜索

本章涵盖了技术面试中遇到的最流行的排序和搜索算法。我们将涵盖诸如归并排序、快速排序、基数排序、堆排序和桶排序等排序算法，以及二分搜索等搜索算法。

通过本章结束时，您应该能够解决涉及排序和搜索算法的各种问题。我们将涵盖以下主题：

+   排序算法

+   搜索算法

+   编码挑战

让我们开始吧！

# 技术要求

您可以在 GitHub 上找到本章的所有代码文件，网址为[`github.com/PacktPublishing/The-Complete-Coding-Interview-Guide-in-Java/tree/master/Chapter14`](https://github.com/PacktPublishing/The-Complete-Coding-Interview-Guide-in-Java/tree/master/Chapter14)。

# 排序算法

从准备面试的人的角度考虑排序算法，可以发现两个主要类别：一个类别包含许多相对简单的排序算法，不会在面试中出现，例如冒泡排序、插入排序、计数排序等，另一个类别包含堆排序、归并排序、快速排序、桶排序和基数排序。这些代表了技术面试中出现的前五个排序算法。

如果您对简单的排序算法不熟悉，那么我强烈建议您购买我的书《Java 编程问题》（[www.packtpub.com/programming/java-coding-problems](http://www.packtpub.com/programming/java-coding-problems)），由 Packt 出版。在《Java 编程问题》的*第五章**，数组、集合和数据结构*中，您可以找到对冒泡排序、插入排序、计数排序等的详细介绍。

此外，名为*SortArraysIn14Ways*的应用程序包含了您应该了解的 14 种不同排序算法的实现。完整列表如下：

+   冒泡排序

+   带有`Comparator`的冒泡排序

+   优化的冒泡排序

+   优化的带有`Comparator`的冒泡排序

+   煎饼排序

+   交换排序

+   选择排序

+   希尔排序

+   插入排序

+   带有`Comparator`的插入排序

+   计数排序

+   归并排序

+   堆排序

+   带有`Comparator`的堆排序

+   桶排序

+   鸡尾酒排序

+   循环排序

+   快速排序

+   带有`Comparator`的快速排序

+   基数排序

在接下来的章节中，我们将简要概述面试中遇到的主要算法：堆排序、归并排序、快速排序、桶排序和基数排序。如果您已经熟悉这些算法，请考虑直接跳转到*搜索算法*部分，甚至是*编码挑战*部分。

## 堆排序

如果您对堆的概念不熟悉，请考虑阅读*第十三章**，树和图*中的*二叉堆*部分。

堆排序是一种依赖于二叉堆（完全二叉树）的算法。时间复杂度分别为：最佳情况 O(n log n)，平均情况 O(n log n)，最坏情况 O(n log n)。空间复杂度为 O(1)。

通过最大堆（父节点始终大于或等于子节点）对元素进行升序排序，通过最小堆（父节点始终小于或等于子节点）对元素进行降序排序。

堆排序算法有几个主要步骤，如下：

1.  将给定数组转换为最大二叉堆。

1.  接下来，根节点与堆的最后一个元素交换，并且堆的大小减 1（这就像删除堆的根元素）。因此，较大的元素（堆的根）移到最后的位置。换句话说，堆的根元素一个接一个地按排序顺序出来。

1.  最后一步是*堆化*剩余的堆（以自顶向下的递归过程重建最大堆）。

1.  在堆大小大于 1 时重复*步骤 2*。

下面的图表代表了应用堆排序算法的一个测试案例：

![图 14.1 - 堆排序](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_14.1_B15403.jpg)

图 14.1 - 堆排序

举例来说，让我们假设前面图表中的数组；即 4, 5, 2, 7, 1：

1.  所以，在第一步，我们构建最大堆：7, 5, 2, 4, 1（我们用 5 和 7 交换，用 4 和 7 交换，用 4 和 5 交换）。

1.  接下来，将根（7）与最后一个元素（1）交换并删除 7。结果：1, 5, 2, 4, **7**。

1.  此外，我们再次构建最大堆：5, 4, 2, 1（我们用 1 和 5 交换，用 1 和 4 交换）。

1.  我们将根（5）与最后一个元素（1）交换并删除 5。结果：1, 4, 2, **5, 7**。

1.  接下来，我们再次构建最大堆：4, 1, 2（我们用 1 和 4 交换）。

1.  我们将根（4）与最后一个元素（2）交换并删除 4。结果：2, 1, **4, 5, 7**。

1.  这已经是一个最大堆了，所以我们只需将根（2）与最后一个元素（1）交换并移除 2：1, **2, 4, 5, 7**。

1.  完成！堆中只剩下一个元素（1）。所以，最终结果是**1, 2, 4, 5, 7**。

在代码方面，上面的例子可以概括如下：

```java
public static void sort(int[] arr) {
  int n = arr.length;
  buildHeap(arr, n);
  while (n > 1) {
    swap(arr, 0, n - 1);
    n--;
    heapify(arr, n, 0);
  }
}
private static void buildHeap(int[] arr, int n) {
  for (int i = arr.length / 2; i >= 0; i--) {
    heapify(arr, n, i);
  }
}
private static void heapify(int[] arr, int n, int i) {
  int left = i * 2 + 1;
  int right = i * 2 + 2;
  int greater;
  if (left < n && arr[left] > arr[i]) {
    greater = left;
  } else {
    greater = i;
  }
  if (right < n && arr[right] > arr[greater]) {
    greater = right;
  }
  if (greater != i) {
    swap(arr, i, greater);
    heapify(arr, n, greater);
  }
}
private static void swap(int[] arr, int x, int y) {
  int temp = arr[x];
  arr[x] = arr[y];
  arr[y] = temp;
}
```

堆排序不是一个稳定的算法。稳定的算法保证了重复元素的顺序。完整的应用程序称为*HeapSort*。这个应用程序还包含了基于`Comparator`的实现 - 这对于对对象进行排序很有用。

## 归并排序

现在，让我们讨论一下归并排序算法。时间复杂度情况如下：最佳情况 O(n log n)，平均情况 O(n log n)，最坏情况 O(n log n)。空间复杂度可能会有所不同，取决于所选择的数据结构（可能是 O(n)）。

归并排序算法是一种基于著名的*分而治之*策略的递归算法。考虑到你已经得到了一个未排序的数组，应用归并排序算法需要你不断地将数组分成两半，直到得到空的子数组或者只包含一个元素的子数组（这就是*分而治之*）。如果一个子数组是空的或者只包含一个元素，那么它根据定义是已排序的 - 这就是递归的*基本情况*。

如果我们还没有达到*基本情况*，我们再次将这些子数组分割，并尝试对它们进行排序。所以，如果数组包含多于一个元素，我们将其分割，并在这两个子数组上递归调用排序操作。下面的图表显示了对数组 52, 28, 91, 19, 76, 33, 43, 57, 20 的分割过程：

![图 14.2 - 在归并排序算法中分割给定的数组](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_14.2_B15403.jpg)

图 14.2 - 在归并排序算法中分割给定的数组

一旦分割完成，我们调用这个算法的基本操作：*merge*操作（也称为*combine*操作）。合并是将两个较小的排序子数组合并成一个新的排序子数组的操作。这样做直到整个给定的数组排序完成。下面的图表显示了我们数组的合并操作：

![图 14.3 - 归并排序的合并操作](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_14.3_B15403.jpg)

图 14.3 - 归并排序的合并操作

下面的代码实现了归并排序算法。流程从`sort()`方法开始。在这里，我们首先询问*基本情况*的问题。如果数组的大小大于 1，那么我们调用`leftHalf()`和`rightHalf()`方法，这将把给定的数组分成两个子数组。`sort()`中的其余代码负责调用`merge()`方法，对两个未排序的子数组进行排序：

```java
public static void sort(int[] arr) {
  if (arr.length > 1) {
    int[] left = leftHalf(arr);
    int[] right = rightHalf(arr);
    sort(left);
    sort(right);
    merge(arr, left, right);
  }
}
private static int[] leftHalf(int[]arr) {
  int size = arr.length / 2;
  int[] left = new int[size];
  System.arraycopy(arr, 0, left, 0, size);
  return left;
}
private static int[] rightHalf(int[] arr) {
  int size1 = arr.length / 2;
  int size2 = arr.length - size1;
  int[] right = new int[size2];
  for (int i = 0; i < size2; i++) {
    right[i] = arr[i + size1];
  }
  return right;
}
```

接下来，合并操作将元素逐个放回原始数组，重复从排序好的子数组中取出最小的元素：

```java
private static void merge(int[] result, 
      int[] left, int[] right) {
  int t1 = 0;
  int t2 = 0;
  for (int i = 0; i < result.length; i++) {
    if (t2 >= right.length
        || (t1 < left.length && left[t1] <= right[t2])) {
      result[i] = left[t1];
      t1++;
    } else {
      result[i] = right[t2];
      t2++;
    }
  }
}
```

注意`left[t1] <= right[t2]`语句保证了算法的稳定性。稳定的算法保证了重复元素的顺序。

完整的应用程序称为*MergeSort*。

## 快速排序

快速排序是另一种基于著名的*分而治之*策略的递归排序算法。时间复杂度情况如下：最佳情况 O(n log n)，平均情况 O(n log n)，最坏情况 O(n2)。空间复杂度为 O(log n)或 O(n)。

快速排序算法首次选择很重要。我们必须从给定数组中选择一个元素作为*枢轴*。接下来，我们对给定数组进行分区，使得所有小于*枢轴*的元素都排在所有大于它的元素之前。分区操作通过一系列交换进行。这是*分而治之*中的*分*步骤。

接下来，使用相应的枢轴递归地将左侧和右侧子数组再次进行分区。这是*分而治之*中的*征服*步骤。

最坏情况（O(n2)）发生在给定数组的所有元素都小于所选的枢轴或大于所选的枢轴时。可以以至少四种方式选择枢轴元素，如下所示：

+   选择第一个元素作为枢轴。

+   选择最后一个元素作为枢轴。

+   选择中位数作为枢轴。

+   选择随机元素作为枢轴。

考虑数组 4, 2, 5, 1, 6, 7, 3。在这里，我们将把枢轴设置为最后一个元素。下面的图表描述了快速排序的工作原理：

![图 14.4 - 快速排序](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_14.4_B15403.jpg)

图 14.4 - 快速排序

**步骤 1**：我们选择最后一个元素作为枢轴，所以 3 是枢轴。分区开始时，找到两个位置标记 - 让我们称它们为*i*和*m*。最初，两者都指向给定数组的第一个元素。接下来，我们将位置*i*上的元素与枢轴进行比较，因此我们将 4 与 3 进行比较。由于 4 > 3，所以没有什么可做，*i*变为 1（*i*++），而*m*保持为 0。

**步骤 2**：我们将位置*i*上的元素与枢轴进行比较，因此我们将 2 与 3 进行比较。由于 2 < 3，我们交换位置*m*上的元素与位置*i*上的元素，所以我们交换 4 与 2。*m*和*i*都增加了 1，所以*m*变为 1，*i*变为 2。

**步骤 3**：我们将位置*i*上的元素与枢轴进行比较，因此我们将 5 与 3 进行比较。由于 5 > 3，所以没有什么可做的，所以*i*变为 3（*i*++），而*m*保持为 1。

**步骤 4**：我们将位置*i*上的元素与枢轴进行比较，因此我们将 1 与 3 进行比较。由于 1 < 3，我们交换位置*m*上的元素与位置*i*上的元素，所以我们交换 1 与 4。*m*和*i*都增加了 1，所以*m*变为 2，*i*变为 4。

**步骤 5 和 6**：我们继续比较位置*i*上的元素与枢轴。由于 6 > 3 和 7 > 3，在这两个步骤中没有什么可做的。完成这些步骤后，*i*=7。

**步骤 7**：*i*的下一个元素是枢轴本身，因此没有更多的比较要执行。我们只需交换位置*m*上的元素与枢轴，所以我们交换 5 与 3。这将枢轴带到其最终位置。其左侧的所有元素都小于它，而右侧的所有元素都大于它。最后，我们返回*m*。

此外，算法对由 0（*left*）和*m*-1 界定的数组以及由*m*+1 和数组末尾（*right*）界定的数组重复。只要*left*<*right*为真，算法就会重复。当此条件评估为假时，数组就已排序。

快速排序算法的伪代码如下：

```java
sort(array, left, right)
    if left < right
        m = partition(array, left, right)
        sort(array, left, m-1)
        sort(array, m+1, right)
    end
end
partition(array, left, right)
    pivot = array[right]
    m = left
    for i = m to right-1
        if array[i] <= pivot
            swap array[i] with array[m]
            m=m+1
        end 
    end
    swap array[m] with array[right]
    return m
end
```

要对整个数组进行排序，我们调用`sort(array, 0, array.length-1)`。让我们看看它的实现：

```java
public static void sort(int[] arr, int left, int right) {
  if (left < right) {
    int m = partition(arr, left, right);         
    sort(arr, left, m - 1);
    sort(arr, m + 1, right);
  }
}
private static int partition(int[] arr, int left, int right) {
  int pivot = arr[right];
  int m = left;
  for (int i = m; i < right; i++) {
    if (arr[i] <= pivot) {                
      swap(arr, i, m++);                
    }
  }
  swap(arr, right, m);
  return m;
}
```

快速排序可以交换非相邻元素；因此，它不是稳定的。完整的应用程序称为*QuickSort*。该应用程序还包含基于`Comparator`的实现 - 这对于对对象进行排序很有用。

## 桶排序

桶排序（或者称为箱排序）是面试中遇到的另一种排序技术。它在计算机科学中常用，在元素均匀分布在一个范围内时非常有用。时间复杂度情况如下：最好和平均情况为 O(n+k)，其中 O(k)是创建桶的时间（对于链表或哈希表来说是 O(1)），而 O(n)是将给定数组的元素放入桶中所需的时间（对于链表或哈希表来说也是 O(1)）。最坏情况为 O(n2)。空间复杂度为 O(n+k)。

其高潮在于将给定数组的元素分成称为*桶*的组。接下来，使用不同的适当排序算法或使用递归通过桶排序算法单独对每个桶进行排序。

可以通过几种方式来创建桶。一种方法依赖于定义一些桶，并将给定数组中的特定范围的元素填充到每个桶中（这称为*scatter*）。接下来，对每个桶进行排序（通过桶排序或其他排序算法）。最后，从每个桶中收集元素以获得排序后的数组（这称为*gathering*）。这也被称为*scatter-sort-gather*技术，并在下图中进行了示例。在这里，我们在数组 4, 2, 11, 7, 18, 3, 14, 7, 4, 16 上使用桶排序：

![图 14.5 - 通过 scatter-sort-gather 方法进行桶排序](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_14.5_B15403.jpg)

图 14.5 - 通过 scatter-sort-gather 方法进行桶排序

因此，正如前面的图表所显示的，我们为间隔中的元素定义了四个桶，即 0-5, 5-10, 10-15 和 15-20。给定数组的每个元素都适合一个桶。在将给定数组的所有元素分配到桶中后，我们对每个桶进行排序。第一个桶包含元素 2, 3, 4 和 4。第二个桶包含元素 7, 7 等。最后，我们从桶中收集元素（从左到右），并获得排序后的数组；即 2, 3, 4, 4, 7, 7, 11, 14, 16, 18。

因此，对于这个，我们可以编写以下伪代码：

```java
sort(array)
  create N buckets each of which can hold a range of elements
  for all the buckets
    initialize each bucket with 0 values
  for all the buckets
    put elements into buckets matching the range
  for all the buckets 
    sort elements in each bucket
    gather elements from each bucket
end 
```

可以通过列表实现此伪代码，如下所示（在此代码中调用的`hash()`方法在本书附带的代码中可用）：

```java
/* Scatter-Sort-Gather approach */
public static void sort(int[] arr) {
  // get the hash codes 
  int[] hashes = hash(arr);
  // create and initialize buckets
  List<Integer>[] buckets = new List[hashes[1]];
  for (int i = 0; i < hashes[1]; i++) {
    buckets[i] = new ArrayList();
  }
  // scatter elements into buckets
  for (int e : arr) {
    buckets[hash(e, hashes)].add(e);
  }
  // sort each bucket
  for (List<Integer> bucket : buckets) {
    Collections.sort(bucket);
  }
  // gather elements from the buckets
  int p = 0;
  for (List<Integer> bucket : buckets) {
    for (int j : bucket) {
      arr[p++] = j;
    }
  }
}
```

创建桶的另一种方法是将单个元素放入一个桶，如下图所示（这次不涉及排序）：

![图 14.6 - 通过 scatter-gather 方法进行桶排序](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_14.6_B15403.jpg)

图 14.6 - 通过 scatter-gather 方法进行桶排序

在这种*scatter-gather*方法中，我们在每个桶中存储元素的出现次数，而不是元素本身，而桶的位置（索引）代表元素的值。例如，在桶号 2 中，我们存储元素 2 的出现次数，在数组 4, 2, 8, 7, 8, 2, 2, 7, 4, 9 中出现三次。由于给定数组中不存在元素 1, 3, 5 和 6，它们的桶为空（其中有 0）。收集操作从左到右收集元素并获得排序后的数组。

因此，对于这个，我们可以编写以下伪代码：

```java
sort(array)
  create N buckets each of which can track a  
        counter of a single element
  for all the buckets
    initialize each bucket with 0 values
  for all the buckets
    put elements into buckets matching a single 
        element per bucket
  for all the buckets 
    gather elements from each bucket
end 
```

可以通过以下方式实现此伪代码：

```java
/* Scatter-Gather approach */
public static void sort(int[] arr) {
  // get the maximum value of the given array
  int max = arr[0];
  for (int i = 1; i < arr.length; i++) {
    if (arr[i] > max) {
      max = arr[i];
    }
  }
  // create max buckets
  int[] bucket = new int[max + 1];
  // the bucket[] is automatically initialized with 0s, 
  // therefore this step is redundant
  for (int i = 0; i < bucket.length; i++) {
    bucket[i] = 0;
  }
  // scatter elements in buckets
  for (int i = 0; i < arr.length; i++) {
    bucket[arr[i]]++;
  }
  // gather elements from the buckets
  int p = 0;
  for (int i = 0; i < bucket.length; i++) {
    for (int j = 0; j < bucket[i]; j++) {
      arr[p++] = i;
    }
  }
}
```

桶排序不是一个稳定的算法。稳定的算法保证了重复元素的顺序。完整的应用程序称为*BucketSort*。

## 基数排序

基数排序是一种非常适用于整数的排序算法。在基数排序中，我们通过将数字的各个数字按其在数字中的位置进行分组来对元素进行排序。接下来，我们通过对每个重要位置上的数字进行排序来对元素进行排序。通常，这是通过计数排序来完成的（计数排序算法在 Packt 出版的书籍*Java Coding Problems*中有详细介绍，但您也可以在名为*SortArraysIn14Ways*的应用程序中找到其实现）。主要的，可以通过任何稳定的排序算法来对数字进行排序。

理解基数排序算法的简单方法是通过一个例子。让我们考虑数组 323, 2, 3, 123, 45, 6, 788。下图展示了按顺序对这个数组进行排序的步骤，依次对个位数、十位数和百位数进行排序：

![图 14.7 – 基数排序](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_14.7_B15403.jpg)

图 14.7 – 基数排序

所以，首先，我们根据个位数对元素进行排序。其次，我们根据十位数对元素进行排序。第三，我们根据百位数对元素进行排序。当然，根据数组中的最大数，这个过程会继续到千位、万位，直到没有更多的数字为止。

以下代码是基数排序算法的实现：

```java
public static void sort(int[] arr, int radix) {
  int min = arr[0];
  int max = arr[0];
  for (int i = 1; i < arr.length; i++) {
    if (arr[i] < min) {
      min = arr[i];
    } else if (arr[i] > max) {
      max = arr[i];
    }
  }
  int exp = 1;
  while ((max - min) / exp >= 1) {
    countSortByDigit(arr, radix, exp, min);
    exp *= radix;
  }
}
private static void countSortByDigit(
    int[] arr, int radix, int exp, int min) {
  int[] buckets = new int[radix];
  for (int i = 0; i < radix; i++) {
    buckets[i] = 0;
  }
  int bucket;
  for (int i = 0; i < arr.length; i++) {
    bucket = (int) (((arr[i] - min) / exp) % radix);
    buckets[bucket]++;
  }
  for (int i = 1; i < radix; i++) {
    buckets[i] += buckets[i - 1];
  }
  int[] out = new int[arr.length];
  for (int i = arr.length - 1; i >= 0; i--) {
    bucket = (int) (((arr[i] - min) / exp) % radix);
    out[--buckets[bucket]] = arr[i];
  }
  System.arraycopy(out, 0, arr, 0, arr.length);
}
```

基数排序的时间复杂度取决于用于对数字进行排序的算法（请记住，这可以是任何稳定的排序算法）。由于我们使用计数排序算法，时间复杂度为 O(d(n+b))，其中*n*是元素的数量，*d*是数字的数量，*b*是基数（在我们的情况下，基数是 10）。空间复杂度为 O(n+b)。

完整的应用程序称为*RadixSort*。到目前为止，我们已经涵盖了技术面试中出现的前五种排序算法。现在，让我们快速概述搜索算法。

# 搜索算法

在面试中经常出现的主要搜索算法是二分搜索算法，它可能作为一个独立的问题或其他问题的一部分。最佳情况时间复杂度为 O(1)，而平均和最坏情况为 O(log n)。二分搜索的最坏情况辅助空间复杂度为 O(1)（迭代实现）和 O(log n)（递归实现）。

二分搜索算法依赖于“分而治之”的策略。主要是通过将给定的数组分成两个子数组来开始。此外，它会丢弃其中一个子数组，并迭代或递归地对另一个子数组进行操作。换句话说，在每一步中，该算法将搜索空间减半（最初是整个给定数组）。

因此，这些算法描述了在数组*a*中查找元素*x*的步骤。考虑一个包含 16 个元素的排序数组*a*，如下图所示：

![图 14.8 – 包含 16 个元素的有序数组](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_14.8_B15403.jpg)

图 14.8 – 包含 16 个元素的有序数组

首先，我们将*x*与数组的中点*p*进行比较。如果它们相等，我们返回。如果*x > p*，那么我们在数组的右侧搜索并丢弃左侧（搜索空间是数组的右侧）。如果*x < p*，那么我们在数组的左侧搜索并丢弃右侧（搜索空间是数组的左侧）。以下是用于查找数字 17 的二分搜索算法的图形表示：

![图 14.9 – 二分搜索算法](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_14.9_B15403.jpg)

图 14.9 – 二分搜索算法

注意我们从 16 个元素开始，最后只剩下 1 个。第一步之后，我们剩下 16/2 = 8 个元素。第二步之后，我们剩下 8/2 = 4 个元素。第三步之后，我们剩下 4/2 = 2 个元素。最后一步，我们找到了搜索的数字 17。如果我们将这个算法转换成伪代码，那么我们将得到类似以下的内容：

```java
search 17 in {1, 4, 5, 7, 10, 16, 17, 18, 20,  
              23, 24, 25, 26, 30, 31, 33}
    compare 17 to 18 -> 17 < 18
    search 17 in {1, 4, 5, 7, 10, 16, 17, 18}
        compare 17 to 7 -> 17 > 7
        search 17 in {7, 10, 16, 17}
            compare 17 to 16 -> 17 > 16
            search 17 in {16, 17}
                compare 17 to 17
                return
```

迭代实现如下所示：

```java
public static int runIterative(int[] arr, int p) {
  // the search space is the whole array
  int left = 0;
  int right = arr.length - 1;
  // while the search space has at least one element
  while (left <= right) {
    // half the search space
    int mid = (left + right) / 2;
    // if domain overflow can happen then use:
    // int mid = left + (right - left) / 2;
    // int mid = right - (right - left) / 2;
    // we found the searched element 
    if (p == arr[mid]) {
      return mid;
    } // discard all elements in the right of the 
      // search space including 'mid'
    else if (p < arr[mid]) {
      right = mid - 1;
    } // discard all elements in the left of the 
      // search space including 'mid'
    else {
      left = mid + 1;
    }
  }
  // by convention, -1 means element not found into the array
  return -1;
}
```

完整的应用程序称为*BinarySearch*。它还包含了二分查找算法的递归实现。在*第十章**，数组和字符串*中，你可以找到利用二分查找算法的不同编码挑战。

# 编码挑战

到目前为止，我们已经涵盖了在技术面试中遇到的最流行的排序和搜索算法。建议你练习这些算法，因为它们可能作为独立的问题出现，需要伪代码或实现。

说到这里，让我们来解决与排序和搜索算法相关的 18 个问题。

## 编码挑战 1 – 合并两个排序好的数组

**亚马逊**，**谷歌**，**Adobe**，**微软**，**Flipkart**

**问题**：假设你已经得到了两个排序好的数组*p*和*q*。*p*数组足够大，可以容纳*q*放在其末尾。编写一段代码片段，将*p*和*q*按排序顺序合并。

**解决方案**：重要的是要强调*p*在末尾有足够的空间容纳*q*。这表明解决方案不应涉及任何辅助空间。解决方案应该通过按顺序将*q*中的元素插入到*p*中，输出合并*p*和*q*的结果。

主要是，我们应该比较*p*和*q*中的元素，并按顺序将它们插入到*p*中，直到我们处理完*p*和*q*中的所有元素。让我们看一个有意义的图表，揭示了这个动作（*p*包含元素-1, 3, 8, 0, 0，而*q*包含元素 2, 4）：

![图 14.10 – 合并两个排序好的数组](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_14.10_B15403.jpg)

图 14.10 – 合并两个排序好的数组

让我们逐步看这个测试案例（让我们用*p*的最后一个元素的索引表示为*pIdx*，用*q*的最后一个元素的索引表示为*qIdx*）。在前面的图中，*pIdx*=2（对应元素 8），*qIdx*=1（对应元素 4）。

**步骤 1**：我们比较*p*的最后一个元素（索引*pIdx*处的元素）和*q*的最后一个元素（索引*qIdx*处的元素），所以我们比较 8 和 4。由于 8 > 4，我们将 8 复制到*p*的末尾。由于两个数组都是排序好的，8 是这些数组中的最大值，所以它必须放在*p*的最后位置（索引）。它将占据*p*中的一个空槽（记住*p*足够大，可以容纳*q*在其末尾）。我们将*pIdx*减 1。

**步骤 2**：我们比较*p*的最后一个元素（索引*pIdx*处的元素）和*q*的最后一个元素（索引*qIdx*处的元素），所以我们比较 3 和 4。由于 3 < 4，我们将 4 复制到*p*的末尾。我们将*qIdx*减 1。

**步骤 3**：我们比较*p*的最后一个元素（索引*pIdx*处的元素）和*q*的最后一个元素（索引*qIdx*处的元素），所以我们比较 3 和 2。由于 3 > 2，我们将 3 复制到*p*的末尾。我们将*pIdx*减 1。

**步骤 4**：我们比较*p*的最后一个元素（索引*pIdx*处的元素）和*q*的最后一个元素（索引*qIdx*处的元素），所以我们比较-1 和 2。由于-1 < 2，我们将 2 复制到*p*的末尾。我们将*qIdx*减 1。没有更多的元素可以比较，*p*已经排序。

看看这个！在每次比较之后，我们将元素插入到*p*的末尾。这样，我们就不需要移动任何元素。然而，如果我们选择将元素插入到*p*的开头，那么我们必须将元素向后移动，为每个插入的元素腾出空间。这是不高效的！

现在，是时候看看这个算法的实现了：

```java
public static void merge(int[] p, int[] q) {
  int pLast = p.length - q.length;
  int qLast = q.length;
  if (pLast < 0) {
    throw new IllegalArgumentException("p cannot fit q");
  }
  int pIdx = pLast - 1;
  int qIdx = qLast - 1;
  int mIdx = pLast + qLast - 1;
  // merge p and q
  // start from the last element in p and q
  while (qIdx >= 0) {
    if (pIdx >= 0 && p[pIdx] > q[qIdx]) {
      p[mIdx] = p[pIdx];
      pIdx--;
    } else {
      p[mIdx] = q[qIdx];
      qIdx--;
    }
    mIdx--;
  }
}
```

完整的应用程序称为*MergeTwoSortedArrays*。如果你想检查/记住如何合并*k*个排序数组，那么请回顾*第十章**，数组和字符串*，*在 O(nk log k)时间内合并 k 个排序数组*编码挑战。

## 编码挑战 2 - 将变位词分组在一起

**Adobe**，**Flipkart**

**问题**：考虑到你已经得到了一个包含来自'a'到'z'的字符的单词数组，代表了几个混合的变位词（例如，“calipers”，“caret”，“slat”，“cater”，“thickset”，“spiracle”，“trace”，“last”，“salt”，“bowel”，“crate”，“loop”，“polo”，“thickest”，“below”，“thickets”，“pool”，“elbow”，“replicas”）。编写一小段代码，以便打印这个数组，以便所有的变位词都被分组在一起（例如，“calipers”，“spiracle”，“replicas”，“caret”，“cater”，“trace”，“crate”，“slat”，“last”，“salt”，“bowel”，“below”，“elbow”，“thickset”，“thickest”，“thickets”，“loop”，“polo”，“pool”）。

**解决方案**：首先，这里有一个关于变位词的快速提醒。如果两个或更多字符串（单词）包含相同的字符但顺序不同，则被认为是变位词。

根据这个问题提供的示例，让我们定义以下混合变位词数组：

```java
String[] words = {
  "calipers", "caret", "slat", "cater", "thickset",   
  "spiracle", "trace", "last", "salt", "bowel", "crate", 
  "loop", "polo", "thickest", "below", "thickets", 
  "pool", "elbow", "replicas"
};
```

由于变位词包含完全相同的字符，这意味着如果我们对它们进行排序，它们将是相同的（例如，对“slat”，“salt”和“last”进行排序得到“alst”）。因此，我们可以说两个字符串（单词）通过比较它们的排序版本来判断它们是否是变位词。换句话说，我们只需要一个排序算法。这样做的最方便的方法是依赖于 Java 的内置排序算法，对于基本类型是双轴快速排序，对于对象是 TimSort。

内置解决方案称为`sort()`，在`java.util.Arrays`类中有很多不同的版本（15+种）。其中两种版本具有以下签名：

+   `void sort(Object[] a)`

+   `<T> void sort(T[] a, Comparator<? super T> c)`

如果我们将一个字符串（单词）转换为`char[]`，然后对其字符进行排序并通过以下辅助方法返回新的字符串：

```java
// helper method for sorting the chars of a word
private static String sortWordChars(String word) {
  char[] wordToChar = word.toCharArray();
  Arrays.sort(wordToChar);
  return String.valueOf(wordToChar);
}
```

接下来，我们只需要一个`Comparator`，指示彼此是变位词的两个字符串是等价的：

```java
public class Anagrams implements Comparator<String> {
  @Override
  public int compare(String sl, String s2) {
    return sortStringChars(sl).compareTo(sortStringChars(s2));
  }
}
```

最后，我们通过这个`compareTo()`方法对给定的字符串（单词）数组进行排序：

```java
Arrays.sort(words, new Anagrams());
```

然而，问题实际上并没有要求我们对给定的变位词数组进行排序；问题要求我们打印分组在一起的变位词。为此，我们可以依赖*哈希*（如果你不熟悉哈希的概念，请阅读*第六章**，面向对象编程*，*哈希表*问题）。在 Java 中，我们可以通过内置的`HashMap`实现使用哈希，因此无需从头开始编写哈希实现。但是`HashMap`有什么用呢？这个映射的条目（键值对）应该存储什么？

每组变位词都会收敛到相同的排序版本（例如，包含字符串（单词）“slat”，“salt”和“last”的变位词组具有唯一和共同的排序版本“alst”）。由于唯一，排序版本是成为我们映射中键的一个很好的候选者。接下来，值表示变位词的列表。因此，算法非常简单；它包含以下步骤：

1.  循环遍历给定的单词数组。

1.  对每个单词的字符进行排序。

1.  填充映射（添加或更新映射）。

1.  打印结果。

在代码行中：

```java
/* Group anagrams via hashing (O(nm log m) */
public void printAnagrams(String words[]) {
  Map<String, List<String>> result = new HashMap<>();
  for (int i = 0; i < words.length; i++) {
    // sort the chars of each string
    String word = words[i];
    String sortedWord = sortWordChars(word);
    if (result.containsKey(sortedWord)) {
      result.get(sortedWord).add(word);
    } else {
      // start a new group of anagrams
      List<String> anagrams = new ArrayList<>();
      anagrams.add(word);
      result.put(sortedWord, anagrams);
    }
  }
  // print the result
  System.out.println(result.values());
}
```

如果*n*是字符串（单词）的数量，每个字符串（单词）最多有*m*个字符，则前面两种方法的时间复杂度是 O(nm log m)。

我们能做得更好吗？嗯，要做得更好，我们必须确定前两种方法的问题。问题在于我们对每个字符串（单词）进行排序，这将花费额外的时间。然而，我们可以使用额外的`char[]`来计算字符串（单词）中每个字符的出现次数（频率）。构建了这个`char[]`之后，我们将其转换为`String`，以获得我们在`HashMap`中搜索的键。由于 Java 处理`char`类型与（无符号）`short`相同，我们可以使用`char`进行计算。让我们看看代码（`wordToChar`数组跟踪给定数组中每个字符串（单词）的字符频率，从*a*到*z*）：

```java
/* Group anagrams via hashing (O(nm)) */
public void printAnagramsOptimized(String[] words) {
  Map<String, List<String>> result = new HashMap<>();
  for (int i = 0; i < words.length; i++) {
    String word = words[i];
    char[] wordToChar = new char[RANGE_a_z];
    // count up the number of occurrences (frequency) 
    // of each letter in 'word'
    for (int j = 0; j < word.length(); j++) {
      wordToChar[word.charAt(j) - 'a']++;
    }
    String computedWord = String.valueOf(wordToChar);
    if (result.containsKey(computedWord)) {
      result.get(computedWord).add(word);
    } else {
      List<String> anagrams = new ArrayList<>();
      anagrams.add(word);
      result.put(computedWord, anagrams);
    }
  }
  System.out.println(result.values());
}
```

如果*n*是字符串（单词）的数量，每个字符串（单词）包含最多*m*个字符，则前两种方法的时间复杂度为 O(nm)。如果你需要支持更多的字符，而不仅仅是从*a*到*z*，那么使用`int[]`数组和`codePointAt()` - 更多细节请参考*第十章**，数组和字符串*，在*提取代理对的代码点*编码挑战中。完整的应用程序称为*GroupSortAnagrams*。

## 编码挑战 3 - 未知大小的列表

`size()`或类似的方法）仅包含正数。该列表的代码如下：

```java
public class SizelessList {
  private final int[] arr;
  public SizelessList(int[] arr) {
    this.arr = arr.clone();
  }
  public int peekAt(int index) {
    if (index >= arr.length) {
      return -1;
    }
    return arr[index];
  }
}
```

然而，正如你所看到的，有一种方法叫做`peekAt()`，它以 O(1)返回给定索引处的元素。如果给定的索引超出了列表的范围，那么`peekAt()`返回-1。编写一小段代码，返回元素*p*出现的索引。

`list.size()/2`)来找到中间点。给定的数据结构（列表）不会显示其大小。

因此，问题被简化为找到这个列表的大小。我们知道如果给定的索引超出了列表的范围，`peekAt()`会返回-1，所以我们可以循环列表并计算迭代次数，直到`peekAt()`返回-1。当`peekAt()`返回-1 时，我们应该知道列表的大小，所以我们可以应用二分搜索算法。我们可以尝试以指数方式而不是逐个元素地循环列表（线性算法）。因此，我们可以在 O(log n)的时间内完成，其中*n*是列表的大小。我们之所以能够这样做，是因为给定的列表是排序的！

以下代码应该阐明这种方法和其余细节：

```java
public static int search(SizelessList sl, int element) {
  int index = 1;
  while (sl.peekAt(index) != -1
        && sl.peekAt(index) < element) {
    index *= 2;
  }
  return binarySearch(sl, element, index / 2, index);
}
private static int binarySearch(SizelessList sl, 
      int element, int left, int right) {
  int mid;
  while (left <= right) {
    mid = (left + right) / 2;
    int middle = sl.peekAt(mid);
    if (middle > element || middle == -1) {
      right = mid - 1;
    } else if (middle < element) {
      left = mid + 1;
    } else {
      return mid;
    }
  }
  return -1;
}
```

完整的应用程序称为*UnknownSizeList*。

## 编码挑战 4 - 对链表进行归并排序

亚马逊，谷歌，Adobe，微软，Flipkart

**问题**：假设你已经得到了一个单链表。编写一小段代码，使用归并排序算法对这个链表进行排序。

**解决方案**：解决这个问题需要对我们在本书中已经涵盖的几个主题有所了解。首先，你必须熟悉链表。这个主题在*第十一章**，链表和映射*中有所涵盖。其次，你需要阅读本章的*归并排序*部分。

根据归并排序算法，我们必须不断将链表一分为二，直到获得空子列表或包含单个元素的子列表（这是*分而治之*的方法）。如果子列表为空或包含一个元素，它就是按定义排序的 - 这被称为*基本情况*递归。以下图表展示了对初始链表 2 → 1 → 4 → 9 → 8 → 3 → 7 → null 进行此过程：

![图 14.11 - 在链表上使用分而治之](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_14.11_B15403.jpg)

图 14.11 - 在链表上使用分而治之

通过快速运行者/慢速运行者方法可以将给定的链表分成这样。这种方法在*第十一章**，链表和映射*中的*快速运行者/慢速运行者方法*部分有详细介绍。主要是，当**快速运行者**（**FR**）到达给定链表的末尾时，**慢速运行者**（**SR**）指向此列表的中间位置，因此我们可以将列表分成两部分。此代码如下所示：

```java
// Divide the given linked list in two equal sub-lists.
// If the length of the given linked list is odd, 
// the extra node will go in the first sub-list
private Node[] divide(Node sourceNode) {
  // length is less than 2
  if (sourceNode == null || sourceNode.next == null) {
    return new Node[]{sourceNode, null};
  }
  Node fastRunner = sourceNode.next;
  Node slowRunner = sourceNode;
  // advance 'firstRunner' two nodes, 
  // and advance 'secondRunner' one node
  while (fastRunner != null) {
    fastRunner = fastRunner.next;
    if (fastRunner != null) {
      slowRunner = slowRunner.next;
      fastRunner = fastRunner.next;
    }
  }
  // 'secondRunner' is just before the middle point 
  // in the list, so split it in two at that point
  Node[] headsOfSublists = new Node[]{
          sourceNode, slowRunner.next};
  slowRunner.next = null;
  return headsOfSublists;
}
```

代码的其余部分是经典的归并排序实现。`sort()`方法负责递归地对子列表进行排序。接下来，`merge()`方法通过反复从排序后的子列表中取出最小的元素，将元素逐个放回原始链表中：

```java
// sort the given linked list via the Merge Sort algorithm
public void sort() {
  head = sort(head);
}
private Node sort(Node head) {
  if (head == null || head.next == null) {
    return head;
  }
  // split head into two sublists
  Node[] headsOfSublists = divide(head);
  Node head1 = headsOfSublists[0];  
  Node head2 = headsOfSublists[1];
  // recursively sort the sublists
  head1 = sort(head1);
  head2 = sort(head2);
  // merge the two sorted lists together
  return merge(head1, head2);
}
// takes two lists sorted in increasing order, and merge 
// their nodes together (which is returned)
private Node merge(Node head1, Node head2) {
  if (head1 == null) {
    return head2;
  } else if (head2 == null) {
    return head1;
  }
  Node merged;
  // pick either 'head1' or 'head2'
  if (head1.data <= head2.data) {
    merged = head1;
    merged.next = merge(head1.next, head2);
  } else {
    merged = head2;
    merged.next = merge(head1, head2.next);
  }
  return merged;
}
```

完整的应用程序称为*MergeSortSinglyLinkedList*。对双向链表进行排序非常类似。您可以在名为*MergeSortDoublyLinkedList*的应用程序中找到这样的实现。

## 编码挑战 5-字符串与空字符串交错

亚马逊，谷歌，Adobe，微软，Flipkart

**问题**：假设您已经获得了一个包含空字符串的排序字符串数组。编写一小段代码，返回给定非空字符串的索引。

**解决方案**：当我们必须在排序的数据结构中进行搜索（例如，在排序的数组中），我们知道二分搜索算法是正确的选择。那么，在这种情况下我们可以使用二分搜索吗？我们有给定数组的大小，因此可以将搜索空间减半并找到中点。如果我们将数组的索引 0 表示为*left*，将*array.length-*1 表示为*right*，那么我们可以写*mid =*（*left* + *right*）/2。因此，*mid*是给定数组的中点。

但是如果*中间*索引落在一个空字符串上怎么办？在这种情况下，我们不知道是应该去*右边*还是*左边*。换句话说，应该丢弃哪一半，哪一半应该用于继续搜索？答案可以在下图中找到（给定的字符串是"cat"，""，""，""，""，""，""，"rear"，""）：

![图 14.12-在空字符串情况下计算中点](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_14.12_B15403.jpg)

图 14.12-在空字符串情况下计算中点

因此，当中点（*mid*）落在一个空字符串上时，我们必须通过将其移动到最近的非空字符串来更正其索引。如前图的*步骤 2*所示，我们选择*leftMid*为*mid*-1，*rightMid*为*mid*+1。我们不断远离*mid*，直到*leftMid*或*rightMid*索引指向一个非空字符串（在前图中，*rightMid*在*步骤 3*和*4*之后找到字符串"rear"）。当发生这种情况时，我们更新*mid*位置并继续经典的二分搜索（*步骤 4*）。

在代码方面，这非常简单：

```java
public static int search(String[] stringsArr, String str) {
  return search(stringsArr, str, 0, stringsArr.length - 1);
}
private static int search(String[] stringsArr, 
      String str, int left, int right) {
  if (left > right) {
    return -1;
  }
  int mid = (left + right) / 2;
  // since mid is empty we try to find the 
  // closest non-empty string to mid
  if (stringsArr[mid].isEmpty()) {
    int leftMid = mid - 1;
    int rightMid = mid + 1;
    while (true) {
      if (leftMid < left && rightMid > right) {
        return -1;
      } else if (rightMid <= right 
            && !stringsArr[rightMid].isEmpty()) {
        mid = rightMid;
        break;
      } else if (leftMid >= left 
            && !stringsArr[leftMid].isEmpty()) {
        mid = leftMid;
        break;
      }
      rightMid++;
      leftMid--;
    }
  }
  if (str.equals(stringsArr[mid])) {
    // the searched string was found
    return mid;
  } else if (stringsArr[mid].compareTo(str) < 0) {
    // search to the right
    return search(stringsArr, str, mid + 1, right);
  } else {
    // search to the left
    return search(stringsArr, str, left, mid - 1);
  }
}
```

这种方法的最坏时间复杂度为 O(n)。请注意，如果搜索的字符串是空字符串，则返回-1，因此我们将此情况视为错误。这是正确的，因为问题说需要找到的给定字符串是非空的。如果问题没有提供关于这一方面的任何细节，那么您必须与面试官讨论这一点。这样，您向面试官表明您注意细节和边缘情况。完整的应用程序称为*InterspersedEmptyStrings*。

## 编码挑战 6-使用另一个队列对队列进行排序

亚马逊，谷歌，Adobe，微软，Flipkart

**问题**：假设您已经获得了一个整数队列。编写一小段代码，使用另一个队列（额外队列）对该队列进行排序。

**解决方案**：解决此问题的解决方案必须包括一个额外的队列，因此我们必须考虑如何在对给定队列进行排序时使用这个额外的队列。有不同的方法，但是在面试中的一个方便的方法可以总结如下：

1.  只要给定队列中的元素按升序排列（从队列的前端开始），我们就将它们出列并排队到额外队列中。

1.  如果一个元素违反了前面的陈述，那么我们将其出列并重新排队到给定队列中，而不触及额外队列。

1.  在所有元素通过*步骤 1*或*2*进行处理之后，我们将所有元素从额外队列中出列并重新排队到给定队列中。

1.  只要额外队列的大小不等于给定队列的初始大小，我们就从*步骤 1*开始重复，因为队列还没有排序。

让我们假设给定队列包含以下元素：rear → 3 → 9 → 1 → 8 → 5 → 2 → front。下图表示给定队列和额外队列（最初为空）：

![图 14.13 - 给定队列和额外队列](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_14.13_B15403.jpg)

图 14.13 - 给定队列和额外队列

应用我们算法的*步骤 1*意味着从给定队列中出列 2、5 和 8，并将它们排队到额外队列中，如下图所示：

![图 14.14 - 在额外队列中排队 2、5 和 8](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_14.14_B15403.jpg)

图 14.14 - 在额外队列中排队 2、5 和 8

由于给定队列中的下一个元素比添加到额外队列的最后一个元素小，我们应用我们算法的*步骤 2*，所以我们出列 1 并将其排队到给定队列中，如下图所示：

![图 14.15 - 从给定队列中出列并排队 1](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_14.15_B15403.jpg)

图 14.15 - 从给定队列中出列并排队 1

此外，我们再次应用*步骤 1*，因为 9（给定队列的前端）比添加到额外队列的最后一个元素（8）大。所以，9 进入额外队列，如下图所示：

![图 14.16 - 在额外队列中排队 9](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_14.16_B15403.jpg)

图 14.16 - 在额外队列中排队 9

接下来，3 小于 9，所以我们必须将其出列并重新排队到给定队列中，如下图所示：

![图 14.17 - 从给定队列中出列并排队 3](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_14.17_B15403.jpg)

图 14.17 - 从给定队列中出列并排队 3

此时，我们已经处理（访问）了给定队列中的所有元素，所以我们应用我们算法的*步骤 3*。我们将所有元素从额外队列中出列并排队到给定队列中，如下图所示：

![图 14.18 - 从额外队列中出列并加入给定队列](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_14.18_B15403.jpg)

图 14.18 - 从额外队列中出列并加入给定队列

现在，我们重复整个过程，直到给定队列按升序排序。让我们看看代码：

```java
public static void sort(Queue<Integer> queue) {
  if (queue == null || queue.size() < 2) {
    return;
  }
  // this is the extra queue
  Queue<Integer> extraQueue = new ArrayDeque();
  int count = 0;            // count the processed elements
  boolean sorted = false;   // flag when sorting is done
  int queueSize = queue.size();   // size of the given queue
  int lastElement = queue.peek(); // we start from the front  
                                  // of the given queue
  while (!sorted) {
    // Step 1
    if (lastElement <= queue.peek()) {
      lastElement = queue.poll();
      extraQueue.add(lastElement);
    } else { // Step 2
      queue.add(queue.poll());
    }
    // still have elements to process
    count++;
    if (count != queueSize) {
      continue;
    }
    // Step 4
    if (extraQueue.size() == queueSize) {
      sorted = true;
    }
    // Step 3            
    while (extraQueue.size() > 0) {
      queue.add(extraQueue.poll());
      lastElement = queue.peek();
    }
    count = 0;
  }
}
```

这段代码的运行时间是 O(n2)。完整的应用程序称为*SortQueueViaTempQueue*。

## 编码挑战 7 - 在不使用额外空间的情况下对队列进行排序

**亚马逊**，**谷歌**，**Adobe**，**微软**，**Flipkart**

**问题**：假设你有一个整数队列。编写一小段代码，对这个队列进行排序，而不使用额外的空间。

**解决方案**：在前面的问题中，我们必须解决相同的问题，但是使用额外的队列。这一次，我们不能使用额外的队列，所以我们必须在原地对队列进行排序。

我们可以将排序看作是一个持续的过程，从给定队列中找到最小元素，将其从当前位置提取出来，并将其添加到队列的末尾。扩展这个想法可能会得到以下算法：

1.  将当前最小值视为`Integer.MAX_VALUE`。

1.  从队列的未排序部分（最初，未排序部分是整个队列）中出列一个元素。

1.  将这个元素与当前最小值进行比较。

1.  如果这个元素比当前最小值小，那么执行以下操作：

a. 如果当前最小值是`Integer.MAX_VALUE`，那么这个元素就成为当前最小值，我们不会将其重新加入队列。

b. 如果当前最小值不是`Integer.MAX_VALUE`，那么我们将当前最小值重新加入队列，并且这个元素成为当前最小值。

1.  如果这个元素大于当前最小值，则将其重新加入队列。

1.  重复从*步骤 2*直到整个未排序部分被遍历。

1.  在这一步中，当前最小值是整个未排序部分的最小值，因此我们将其重新加入队列。

1.  设置未排序部分的新边界，并从*步骤 1*重复，直到未排序部分的大小为 0（每次执行此步骤时，未排序部分的大小减 1）。

下图是该算法对队列的快照；即，rear → 3 → 9 → 1 → 8 → 5 → 2 → front：

![图 14.19 – 不使用额外空间对队列进行排序](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_14.19_B15403.jpg)

图 14.19 – 不使用额外空间对队列进行排序

注意每个未排序部分（最初是整个队列）的最小值是如何重新加入队列并成为队列的排序部分的成员的。让我们看看代码：

```java
public static void sort(Queue<Integer> queue) {
  // traverse the unsorted part of the queue
  for (int i = 1; i <= queue.size(); i++) {
    moveMinToRear(queue, queue.size() - i);
  }
}
// find (in the unsorted part) the minimum
// element and move this element to the rear of the queue
private static void moveMinToRear(Queue<Integer> queue, 
          int sortIndex) {
  int minElement = Integer.MAX_VALUE;
  boolean flag = false;
  int queueSize = queue.size();
  for (int i = 0; i < queueSize; i++) {
    int currentElement = queue.peek();
    // dequeue
    queue.poll();
    // avoid traversing the sorted part of the queue            
    if (currentElement <= minElement && i <= sortIndex) {
      // if we found earlier a minimum then 
      // we put it back into the queue since
      // we just found a new minimum
      if (flag) {
        queue.add(minElement);
      }
      flag = true;
      minElement = currentElement;
    } else {
      // enqueue the current element which is not the minimum
      queue.add(currentElement);
    }
  }
  // enqueue the minimum element
  queue.add(minElement);
}
```

这段代码的运行时间是 O(n2)。完整的应用程序称为*SortQueueWithoutExtraSpace*。

## 编程挑战 8 – 使用另一个栈帮助对栈进行排序

**亚马逊**，**谷歌**，**Adobe**，**微软**，**Flipkart**

问题：考虑到你已经得到了一个未排序的栈。编写一小段代码，对栈进行升序或降序排序。你只能使用一个额外的临时栈。

**解决方案**：如果我们可以使用两个额外的栈，那么我们可以实现一个算法，该算法重复搜索给定栈中的最小值，并将其推入最终或结果栈。第二个额外的栈将用作在搜索给定栈时的缓冲区。然而，问题要求我们只能使用一个额外的临时栈。

由于这个限制，我们被迫从给定的栈（我们将其表示为*s1*）中弹出并按顺序推入另一个栈（我们将其表示为*s2*）。为了实现这一点，我们使用一个临时的或辅助变量（我们将其表示为*t*），如下图所示（给定的栈为 top → 1 → 4 → 5 → 3 → 1 → 2）：

![图 14.20 – 对栈进行排序](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_14.20_B15403.jpg)

图 14.20 – 对栈进行排序

解决方案由两个主要步骤组成：

1.  当*s1*不为空时，执行以下操作：

a. 从*s1*中弹出一个值并将其存储在*t*中（前一个图中显示了值 3 的*动作 1*）。

b. 从*s2*中弹出并将其推入*s1*，只要从*s2*中弹出的值大于*t*或者*s2*不为空（前一个图中的*动作 2*）。

c. 将*t*推入*s2*（前一个图中的*动作 3*）。

1.  一旦*步骤 1*完成，*s1*为空，*s2*已排序。最大值在底部，因此结果栈为 top → 5 → 4 → 3 → 2 → 1 → 1。第二步是将*s2*复制到*s1*。这样，*s1*按*s2*的相反顺序排序，因此最小值在*s1*的顶部（top → 1 → 1 → 2 → 3 → 4 → 5）。

让我们看看代码：

```java
public static void sort(Stack<Integer> stack) {
  Stack<Integer> auxStack = new Stack<>();
  // Step 1 (a, b and c)
  while (!stack.isEmpty()) {
    int t = stack.pop();
    while (!auxStack.isEmpty() && auxStack.peek() > t) {
      stack.push(auxStack.pop());
    }
    auxStack.push(t);
  }
  // Step 2
  while (!auxStack.isEmpty()) {
    stack.push(auxStack.pop());
  }
}
```

完整的代码称为*SortStack*。

## 编程挑战 9 – 原地对栈进行排序

**亚马逊**，**谷歌**，**Adobe**，**微软**，**Flipkart**

`for`，`while`等等。

**解决方案**：在前面的问题中，我们必须解决相同的问题，但是使用一个显式的额外栈。这一次，我们不能使用显式的额外栈，因此我们必须原地对栈进行排序。

假设给定的栈为 top → 4 → 5 → 3 → 8 → 2 →1。解决方案从栈中弹出值开始，直到栈为空。然后，我们将递归调用栈中的值按排序位置插入回给定的栈。

让我们尝试将这种方法应用到我们的栈上。下图显示了从栈中弹出值直到栈为空的过程。在左侧，我们有初始状态。在右侧，我们有结果：

![图 14.21 – 原地对栈进行排序（1）](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_14.21_B15403.jpg)

图 14.21 – 原地对栈进行排序（1）

接下来，只要要推入的当前元素小于当前堆栈的顶部元素或堆栈为空，我们就将其推回到堆栈中。因此，我们将推入 1、2 和 8。我们不推入 3（下一个要推入的元素），因为 3 小于 8（您可以在以下图表中看到这个语句作为*动作 1*）。在这一点上，我们需要为 3 腾出空间，所以我们必须弹出堆栈的顶部，8（您可以在以下图表中看到这个语句作为*动作 2*）。最后，我们推入 3，然后推入 8 到堆栈中（您可以在以下图表中看到这个语句作为*动作 3*）：

![图 14.22 – 原地对堆栈进行排序（2）](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_14.22_B15403.jpg)

图 14.22 – 原地对堆栈进行排序（2）

到目前为止，一切都很顺利！接下来，我们必须重复前面图表中呈现的流程。因此，从递归调用堆栈中推入给定堆栈的下一个元素是 5。但是 5 小于 8，所以我们不能推入它（您可以在以下图表中看到这个语句作为*动作 1*）。在这一点上，我们需要为 5 腾出空间，所以我们必须弹出堆栈的顶部，即 8（您可以在以下图表中看到这个语句作为*动作 2*）。最后，我们推入 5，然后推入 8 到堆栈中（您可以在以下图表中看到这个语句作为*动作 3*）：

![图 14.23 – 原地对堆栈进行排序（3）](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_14.23_B15403.jpg)

图 14.23 – 原地对堆栈进行排序（3）

最后，应该从递归调用堆栈中推入给定堆栈的最后一个元素是 4。然而，4 小于 8，所以我们不能推入它（您可以在以下图表中看到这个语句作为*动作 1*）。在这一点上，我们需要为 4 腾出空间，所以我们必须弹出堆栈的顶部，即 8（您可以在以下图表中看到这个语句作为*动作 2*）。然而，我们仍然不能将 4 推入堆栈，因为 4 小于 5（弹出 8 后的新顶部元素）。我们必须也弹出 5（您可以在以下图表中看到这个语句作为*动作 3*）。现在，我们可以推入 4。接下来，我们推入 5 和 8。您可以在以下图表中看到这一点作为*动作 4*：

![图 14.24 – 原地对堆栈进行排序（4）](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_14.24_B15403.jpg)

图 14.24 – 原地对堆栈进行排序（4）

完成！给定的堆栈已经排序。让我们看看代码：

```java
public static void sort(Stack<Integer> stack) {
  // stack is empty (base case)
  if (stack.isEmpty()) {
    return;
  }
  // remove the top element
  int top = stack.pop();
  // apply recursion for the remaining elements in the stack
  sort(stack);
  // insert the popped element back in the sorted stack
  sortedInsert(stack, top);
}
private static void sortedInsert(
 Stack<Integer> stack, int element) {
  // the stack is empty or the element 
  // is greater than all elements in the stack (base case)
  if (stack.isEmpty() || element > stack.peek()) {
    stack.push(element);
    return;
  }
  // the element is smaller than the top element, 
  // so remove the top element       
  int top = stack.pop();
  // apply recursion for the remaining elements in the stack
  sortedInsert(stack, element);
  // insert the popped element back in the stack
  stack.push(top);
}
```

这段代码的运行时间是 O(n2)，辅助空间是 O(n)用于递归调用堆栈（*n*是给定堆栈中的元素数）。完整的应用程序称为*SortStackInPlace*。

## 编码挑战 10 – 在完全排序的矩阵中搜索

**亚马逊**，**微软**，**Flipkart**

`true`如果给定的整数在这个矩阵中。

**解决方案**：暴力方法非常低效。如果我们尝试迭代矩阵并将每个（*行，列*）整数与搜索的整数进行比较，那么这将导致时间复杂度为 O(mn)，其中*m*是矩阵中的行数，*n*是列数。

另一个解决方案将依赖于二分搜索算法。我们有足够的经验来为排序数组实现这个算法，但是我们能为排序矩阵实现吗？是的，我们可以，这要归功于这个排序矩阵是*完全排序*。更确切地说，由于每行的第一个整数大于前一行的最后一个整数，我们可以将这个矩阵看作长度为*行数* x *列数*的数组。以下图表澄清了这个说法：

![图 14.25 – 完全排序的矩阵作为数组](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_14.25_B15403.jpg)

图 14.25 – 完全排序的矩阵作为数组

因此，如果我们将给定的矩阵视为数组，那么我们可以将应用二分搜索到排序数组的问题减少。没有必要将矩阵物理转换为数组。我们只需要根据以下语句相应地表达二分搜索：

+   数组的最左边整数位于索引 0（让我们将其表示为*left*）。

+   数组的最右边整数位于索引（*行数* x *列数*）- 1（让我们将其表示为*right*）。

+   数组的中间点在(*left + right*) / 2 处。

+   索引的中间点处的整数为*matrix*[*mid / cols*][*mid % cols*]，其中*cols*是矩阵中的列数。

有了这些陈述，我们可以编写以下实现：

```java
public static boolean search(int[][] matrix, int element) {
  int rows = matrix.length;    // number of rows
  int cols = matrix[0].length; // number of columns
  // search space is an array as [0, (rows * cols) - 1]
  int left = 0;
  int right = (rows * cols) - 1;
  // start binary search
  while (left <= right) {
    int mid = (left + right) / 2;
    int midElement = matrix[mid / cols][mid % cols];
    if (element == midElement) {
      return true;
    } else if (element < midElement) {
      right = mid - 1;
    } else {
      left = mid + 1;
    }
  }
  return false;
}
```

前面的代码在 O(log mn)时间内执行，其中*m*是给定矩阵中的行数，*n*是列数。该应用程序称为*SearchInFullSortedMatrix*。

## 编码挑战 11 - 在排序矩阵中搜索

**亚马逊**，**微软**，**Flipkart**

`true`如果给定整数在此矩阵中。

**解决方案**：请注意，这个问题不像前一个编码挑战，因为每行的第一个整数不必大于前一行的最后一个整数。如果我们应用二分搜索算法（就像我们对前一个编码挑战所做的那样），那么我们必须对每一行应用它。由于二分搜索的时间复杂度为 O(log n)，我们必须对每一行应用它，这意味着这种方法将在 O(m log n)时间内执行，其中*m*是给定矩阵中的行数，*n*是列数。

为了找到解决方案，让我们考虑以下图表（一个 4 x 6 的矩阵）：

![图 14.26 - 在排序矩阵中搜索](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_14.26_B15403.jpg)

图 14.26 - 在排序矩阵中搜索

假设我们搜索元素 80，可以在(2, 3)处找到。让我们试着推断这个位置。这个推断的高潮围绕着矩阵有序的行和列。让我们分析列的开始：如果一列的开始大于 80（例如，列 4），那么我们知道 80 不能在该列中，因为该列的开始是该列中的最小元素。此外，80 不能在该列右侧的任何列中找到，因为每列的开始元素必须从左到右递增。此外，我们可以将相同的逻辑应用于行。如果一行的开始大于 80，那么我们知道 80 不能在该行或随后（向下）的行中。

现在，如果我们看列和行的末尾，我们可以得出一些类似的结论（镜像结论）。如果一列的末尾小于 80（例如，列 2），那么我们知道 80 不能在该列中，因为该列的末尾是该列中的最大元素。此外，80 不能在该列左侧的任何列中找到，因为每列的开始元素必须从右到左递减。此外，我们可以将相同的逻辑应用于行。如果一行的末尾小于 80，那么我们知道 80 不能在该行或随后（向上）的行中。

如果我们将这些结论综合起来，我们可以推断出以下结论：

+   如果一列的开始大于*p*，那么*p*必须在该列的左边。

+   如果一行的开始大于*p*，那么*p*必须在该行的上方。

+   如果一列的末尾小于*p*，那么*p*必须在该列的右边。

+   如果一行的末尾小于*p*，那么*p*必须在该行下方。

这已经开始看起来像一个算法。不过，我们还有一件事要决定。我们从哪里开始？从哪一行和哪一列开始？幸运的是，我们有几个选择。例如，我们可以从最大列（0，*最后一列*）开始，并向同一行的左边开始，或者从最大行（*最后一行*，0）开始，并向同一列的上方开始。

假设我们选择从最大列（0，*最后一列*）开始，并向左查找元素*p*。这意味着我们的流程将如下（让我们表示*i*=0 和*j=cols*-1）：

1.  如果*matrix*[*i*][*j*] *> p*，那么在同一行向左移动。这一列的元素肯定大于*matrix*[*i*][*j*]，因此，通过推论，大于*p*。因此，我们丢弃当前列，将*j*减 1，并重复。

1.  如果*matrix*[*i*][*j*] < p，则在同一列向下移动。这一行的元素肯定小于*matrix*[*i*][*j*]，因此，通过推论，也小于*p*。因此，我们丢弃当前行，将*i*增加 1，并重复。

1.  如果*p*等于*matrix*[*i*][*j*]，返回`true`。

如果我们将这个算法应用于在我们的 4 x 6 矩阵中查找元素 80，那么从（0, 5）到（2, 3）的路径将如下所示：

![图 14.27 - 解决方案的路径](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_14.27_B15403.jpg)

图 14.27 - 解决方案的路径

如果我们将这个算法编写成代码，那么我们会得到以下结果：

```java
public static boolean search(int[][] matrix, int element) {
  int row = 0;
  int col = matrix[0].length - 1;
  while (row < matrix.length && col >= 0) {
    if (matrix[row][col] == element) {
      return true;
    } else if (matrix[row][col] > element) {
      col--;
    } else {
      row++;
    }
  }
  return false;
}
```

这个算法的时间复杂度是 O(m+n)，其中*m*是行数，*n*是列数。完整的应用程序称为*SearchInSortedMatrix*。它还包含了这个算法的递归实现。

## 编码挑战 12 - 第一个 1 的位置

**亚马逊**，**谷歌**，**Adobe**

**问题**：假设你得到了一个只包含 0 和 1 值的数组。至少有一个 0 和一个 1。所有的 0 都在前面，然后是 1。编写一小段代码，返回这个数组中第一个 1 的索引。

**解决方案**：考虑数组*arr*=[0, 0, 0, 1, 1, 1, 1]。搜索到的索引是 3，因为*arr*[3]是 1，这是第一个 1。

由于 0 在前面，然后是 1，所以数组是排序的。

注意

由于这是面试中非常常见的话题，我再说一遍：当我们在一个排序的数组中查找东西时，我们必须考虑二分搜索算法。

在这种情况下，二分搜索算法可以很容易地实现。在二分搜索中计算的中间点可以落在 0 或 1 上。由于数组是排序的，如果中间点落在 0 上，那么我们可以确定 1 的第一个值必须在中间点的右侧，所以我们丢弃中间点的左侧。另一方面，如果中间点落在 1 上，那么我们知道 1 的第一个值必须在中间点的左侧，所以我们丢弃中间点的右侧。以下代码阐明了这一点：

```java
public static int firstOneIndex(int[] arr) {
  if (arr == null) {
    return -1;
  }
  int left = 0;
  int right = arr.length - 1;
  while (left <= right) {
    int middle = 1 + (right - left) / 2;
    if (arr[middle] == 0) {
      left = middle + 1;
    } else {
      right = middle - 1;
    }
    if (arr[left] == 1) {
      return left;
    }
  }
  return -1;
}
```

完整的应用程序称为*PositionOfFirstOne*。

## 编码挑战 13 - 两个元素之间的最大差值

**问题**：假设你得到了一个整数数组*arr*。编写一小段代码，返回当较大的整数出现在较小的整数之后时，两个元素之间的最大差值。

**解决方案**：让我们考虑几个例子。

如果给定的数组是 1, 34, 21, 7, 4, 8, 10，那么最大差值是 33（计算为 34（索引 1）- 1（索引 0））。如果给定的数组是 17, 9, 2, 26, 32, 27, 3，那么最大差值是 30（计算为 32（索引 4）- 2（索引 2））。

如果是按升序排序的数组，比如 3, 7, 9, 11，那么最大差值是 11 - 3 = 8，所以这是最大元素和最小元素之间的差值。如果是按降序排序的数组，比如 11, 9, 7, 6，那么最大差值是 6 - 7 = -1，所以最大差值是最接近 0 的差值。

根据这些例子，我们可以考虑几种解决方案。例如，我们可以先计算数组的最小值和最大值。接下来，如果最大值的索引大于最小值的索引，则最大差值是数组的最大值和最小值之间的差值。否则，我们需要计算数组的下一个最小值和最大值，并重复这个过程。这可能导致 O(n2)的时间复杂度。

另一种方法可以通过对数组进行排序来开始。之后，最大差值将是最大元素和最小元素之间的差值（最后一个元素和第一个元素之间的差值）。这可以通过 O(n log n)的运行时间内的排序算法来实现。

如何在 O(n)时间内完成？我们尝试另一种方法，而不是对数组进行排序或计算其最大值或最小值。请注意，如果我们认为*p*是数组中的第一个元素，我们可以计算每个连续元素与*p*之间的差异。在这样做的同时，我们跟踪最大差异并相应地更新它。例如，如果数组是 3, 5, 2, 1, 7, 4，*p*=3，那么最大差异是 7-*p*=7-3=4。然而，如果我们仔细观察，真正的最大差异是 7-1=6，而 1 小于*p*。这导致我们得出结论，当遍历*p*之后的连续元素时，如果当前遍历的元素小于*p*，那么*p*应该变成该元素。在*p*的后继元素之间计算后续差异，直到完全遍历数组或找到另一个小于*p*的元素。在这种情况下，我们重复这个过程。

让我们看看代码：

```java
public static int maxDiff(int arr[]) {
  int len = arr.length;
  int maxDiff = arr[1] - arr[0];
  int marker = arr[0];
  for (int i = 1; i < len; i++) {
    if (arr[i] - marker > maxDiff) { 
      maxDiff = arr[i] - marker;
    }
    if (arr[i] < marker) {
      marker = arr[i];
    }
  }
  return maxDiff;
}
```

这段代码运行时间为 O(n)。完整的应用程序称为*MaxDiffBetweenTwoElements*。

## 编码挑战 14 - 流排名

**问题：**假设你得到了一系列整数流（例如连续的整数值流）。定期地，我们想要检查给定整数*p*的排名。通过排名，我们理解小于或等于*p*的值的数量。实现支持此操作的数据结构和算法。

**解决方案**：让我们考虑以下流：40, 30, 45, 15, 33, 42, 56, 5, 17, 41, 67。45 的排名是 8，5 的排名是 0，17 的排名是 2，依此类推。

蛮力方法可能适用于排序数组。每次生成一个新整数时，我们将其添加到这个数组中。虽然这对于返回给定整数的排名非常方便，但这种方法有一个重要的缺点：每次插入一个元素，我们都必须将大于新整数的元素移动，以为其腾出空间。这是为了在数组按升序排序时维护数组。

一个更好的选择是**二叉搜索树**（**BST**）。BST 维护相对顺序，并插入新整数将相应地更新树。让我们将整数从我们的流添加到二叉搜索树中，如下所示：

![图 14.28 - 流排名的 BST](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_14.28_B15403.jpg)

图 14.28 - 流排名的 BST

假设我们想要找到排名 43。首先，我们将 43 与根节点进行比较，并得出结论 43 必须在根节点 40 的右子树中。然而，根节点的左子树有 5 个节点（显然，它们都小于根节点），因此 43 的排名至少为 6（根节点的左子树的 5 个节点，加上根节点）。接下来，我们将 43 与 45 进行比较，并得出结论 43 必须在 45 的左边，因此排名保持为 5。最后，我们将 43 与 42 进行比较，并得出结论 43 必须在 42 的右子树中。排名必须增加 1，因此 43 的排名为 7。

那么，我们如何用算法概括这个例子呢？在这里，我们注意到，对于每个节点，我们已经知道了其左子树的排名。这不需要每次需要排名时都计算，因为这将非常低效。每次生成新元素并将其插入树中时，我们可以跟踪和更新左子树的排名。在前面的图中，每个节点都有其子树排名在节点上方突出显示。当需要节点的排名时，我们已经知道了其左子树的排名。接下来，我们必须考虑以下递归步骤，通过`int getRank(Node node, int element)`应用：

1.  如果`element`等于`node.element`，则返回`node.leftTreeSize`。

1.  如果`element`在`node`的左边，则返回`getRank(node.left, element)`。

1.  如果`element`在`node`的右边，则返回`node.leftTreeSize + 1 + getRank(node.right, element)`。

如果找不到给定的整数，则返回-1。相关代码如下：

```java
public class Stream {
  private Node root = null;
  private class Node {
    private final int element;
    private int leftTreeSize;
    private Node left;
    private Node right;
    private Node(int element) {
      this.element = element;
      this.left = null;
      this.right = null;
    }     
  }
  /* add a new node into the tree */
  public void generate(int element) {
    if (root == null) {
      root = new Node(element);
    } else {
      insert(root, element);
    }
  }
  private void insert(Node node, int element) {
    if (element <= node.element) {
      if (node.left != null) {
        insert(node.left, element);
      } else {
        node.left = new Node(element);
      }
      node.leftTreeSize++;
    } else {
      if (node.right != null) {
        insert(node.right, element);
      } else {
        node.right = new Node(element);
      }
    }
  }
  /* return rank of 'element' */
  public int getRank(int element) {
    return getRank(root, element);
  }
  private int getRank(Node node, int element) {
    if (element == node.element) {
      return node.leftTreeSize;
    } else if (element < node.element) {
      if (node.left == null) {
        return -1;
      } else {
        return getRank(node.left, element);
      }
    } else {
      int rightTreeRank = node.right == null 
        ? -1 : getRank(node.right, element);
      if (rightTreeRank == -1) {
        return -1;
      } else {
        return node.leftTreeSize + 1 + rightTreeRank;
      }
    }
  }
}
```

前面的代码将在平衡树上以 O(log n)的时间运行，在不平衡树上以 O(n)的时间运行，其中*n*是树中的节点数。完整的应用程序称为*RankInStream*。

## 编码挑战 15 - 山峰和山谷

**亚马逊**，**谷歌**，**Adobe**，**微软**，**Flipkart**

**问题**：假设你得到了一个表示地形高程的正整数数组。如果数组中的整数大于或等于其邻居(相邻整数)，则称该整数为*山峰*。另一方面，如果数组中的整数小于或等于其邻居(相邻整数)，则称该整数为*山谷*。例如，对于数组 4, 5, 8, 3, 2, 1, 7, 8, 5, 9，我们可以看到 8(两者)和 9 是山峰，而 4, 1 和 5(除了最后一个)是山谷。编写一小段代码，将给定的数组排序为交替的山峰和山谷序列。

**解决方案**：乍一看，一个方便的解决方案是从升序排序数组开始。一旦数组按*l1 ≤ l2 ≤ l3 ≤ l4 ≤ l5 ...*排序，我们可以将每个三元组看作*large*(*l1*)≤*larger*(*l2*)≤*largest*(*l3*)。如果我们交换*l2*和*l3*，那么*l1*≤*l3*≥*l2*，所以*l3*变成了山峰。对于下一个三元组，*l2*≤ *l4* ≤ *l5*，我们交换*l4*和*l5*以获得*l2*≤*l5*≥*l4*，所以*l5*是一个山峰。对于下一个三元组，*l4*≤*l6*≤*l7*，我们交换*l6*和*l7*以获得*l4*≤*l7*≥*l6*，所以*l7*是一个山峰。如果我们继续这些交换，那么我们会得到类似这样的结果：*l1*≤*l3*≥*l2*≤*l5*≥*l4*≤*l7*≥*l6* .... 但这样有效吗？由于我们必须对数组进行排序，我们可以说这种解决方案的时间复杂度是 O(n log n)。我们能做得比这更好吗？是的，我们可以！假设我们将我们的数组表示如下：

![图 14.29 - 给定的地形高程数组](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_14.29_B15403.jpg)

图 14.29 - 给定的地形高程数组

现在，我们可以清楚地看到给定数组的山峰和山谷。如果我们关注第一个三元组(4, 5, 8)并尝试获得一个山峰，那么我们必须将中间值(5)与其邻居(相邻整数)的最大值交换。因此，通过将 5 与 max(4, 8)交换，我们得到(4, 8, 5)。因此，8 是一个山峰，可以表示如下：

![图 14.30 - 用 5 交换 8](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_14.30_B15403.jpg)

图 14.30 - 用 5 交换 8

接下来，让我们关注下一个三元组(5, 3, 2)。我们可以通过将 3 与 max(5, 2)交换来获得一个山峰，因此通过将 3 与 5 交换。结果是(3, 5, 2)，如下所示：

![图 14.31 - 用 3 交换 5](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_14.31_B15403.jpg)

图 14.31 - 用 5 交换 3

现在，5 是一个山峰，3 是一个山谷。我们应该继续处理三元组(2, 1, 7)并交换 1 与 7 以获得山峰(2, 7, 1)。下一个三元组将是(1, 8, 5)，并且 8 是一个山峰(没有东西可以交换)。最后，我们得到最终结果，如下图所示：

![图 14.32 - 最终结果](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_14.32_B15403.jpg)

图 14.32 - 最终结果

面试官希望你注意细节并提到它们。例如，当我们将中间值与左值交换时，我们是否可以破坏已经处理过的地形？我们能破坏山谷或山峰吗？答案是否定的，我们不能破坏任何东西。这是因为当我们将中间值与左值交换时，我们已经知道中间值小于左值，左值是一个山谷。因此，我们只是通过在那个位置添加一个更小的值来创建一个更深的山谷。

基于这些陈述，实现是相当简单的。以下代码将澄清任何剩下的细节：

```java
public static void sort(int[] arr) {
  for (int i = 1; i < arr.length; i += 2) {
    int maxFoundIndex = maxElementIndex(arr, i - 1, i, i + 1);
    if (i != maxFoundIndex) {
      swap(arr, i, maxFoundIndex);
    }            
  }
}
private static int maxElementIndex(int[] arr, 
 int left, int middle, int right) {
  int arrLength = arr.length;
  int leftElement = left >= 0 && left < arrLength
    ? arr[left] : Integer.MIN_VALUE;
  int middleElement = middle >= 0 && middle < arrLength
    ? arr[middle] : Integer.MIN_VALUE;
  int rightElement = right >= 0 && right < arrLength
    ? arr[right] : Integer.MIN_VALUE;
  int maxElement = Math.max(leftElement,
    Math.max(middleElement, rightElement));
  if (leftElement == maxElement) {
    return left;
  } else if (middleElement == maxElement) {
    return middle;
  } else {
    return right;
  }
}
```

这段代码的时间复杂度为 O(n)。完整的应用程序称为*PeaksAndValleys*。

## 编码挑战 16 - 最近的左边较小数

**亚马逊**，**谷歌**，**Adobe**，**微软**，**Flipkart**

**问题**：考虑到您已经得到了一个整数数组*arr*，编写一小段代码，找到并打印每个元素的最近较小数，使得较小的元素在左侧。

**解决方案**：让我们考虑给定的数组；即 4, 1, 8, 3, 8, 2, 6, 7, 4, 9。预期结果是 _，_，1，1，3，1，2，6，2，4。从左到右，我们有以下内容：

+   *arr*[0]=4，它的左边没有元素，所以我们打印 _。

+   *arr*[1]=1，它的左边没有比它更小的元素，所以我们打印 _。

+   *arr*[2]=8，它左边最近的较小元素是 1，所以我们打印 1。

+   *arr*[3]=3，它左边最近的较小元素是 1，所以我们打印 1。

+   *arr*[4]=8，它左边最近的较小元素是 3，所以我们打印 3。

+   *arr*[5]=2，它左边最近的较小元素是 1，所以我们打印 1。

+   *arr*[6]=6，它左边最近的较小元素是 2，所以我们打印 2。

+   *arr*[7]=7，它左边最近的较小元素是 6，所以我们打印 6。

+   *arr*[8]=4，它左边最近的较小元素是 2，所以我们打印 2。

+   *arr*[9]=9，它左边最近的较小元素是 4，所以我们打印 4。

一个简单但低效的解决方案依赖于两个循环。外循环可以从第二个元素（索引 1）开始，直到数组的长度（*arr.length*-1），而内循环遍历外循环选择的元素左侧的所有元素。一旦找到一个较小的元素，它就会停止这个过程。这样的算法很容易实现，但运行时间复杂度为 O(n2)。

然而，我们可以通过`Stack`将时间复杂度降低到 O(n)。主要是，我们可以从 0 到*arr.length*-1 遍历给定的数组，并依赖于`Stack`来跟踪到目前为止已经遍历的子序列元素，这些元素小于已经遍历的任何后续元素。虽然这个说法可能听起来很复杂，但让我们通过查看该算法的步骤来澄清一下：

1.  创建一个新的空栈。

1.  对于*arr*的每个元素（*i* = 0 到*arr.length*-1），我们执行以下操作：

a. 当栈不为空且顶部元素大于或等于*arr*[*i*]时，我们从栈中弹出。

b. 如果栈为空，则*arr*[*i*]的左边没有元素。我们可以打印一个表示没有找到元素的符号（例如，-1 或 _）。

c. 如果栈不为空，则*arr*[*i*]的最近较小值是栈的顶部元素。我们可以查看并打印这个元素。

d. 将*arr*[*i*]推入栈中。

在代码方面，我们有以下内容：

```java
public static void leftSmaller(int arr[]) {
  Stack<Integer> stack = new Stack<>();
  // While the top element of the stack is greater than 
  // equal to arr[i] remove it from the stack        
  for (int i = 0; i < arr.length; i++) {
    while (!stack.empty() && stack.peek() >= arr[i]) {
      stack.pop();
    }
    // if stack is empty there is no left smaller element
    if (stack.empty()) {
      System.out.print("_, ");
    } else {
      // the top of the stack is the left smaller element
      System.out.print(stack.peek() + ", ");
    }
    // push arr[i] into the stack
    stack.push(arr[i]);
  }
}
```

这段代码的运行时间为 O(n)，其中*n*是给定数组中的元素数。完整的应用程序称为*FindNearestMinimum*。

## 编码挑战 17 - 单词搜索

**亚马逊**，**谷歌**

如果给定的单词在板上存在，则返回`true`。同一个字母单元格不能被多次使用。

**解决方案**：让我们考虑一下我们有以下的板：

![图 14.33 - 板样本](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_14.33_B15403.jpg)

图 14.33 - 板样本

请记住，这不是我们第一次需要解决需要在网格中找到某条路径的问题。在*第八章**，递归和动态规划*中，我们有*机器人网格*问题，包括*彩色斑点*，*五座塔*，*下落的球*和*骑士之旅*。最后，在*第十二章**，栈和队列*中，我们有*岛屿*。最后，在*第十三章**，树和图*中，我们有*国际象棋骑士*。

根据您从这些问题中积累的经验，挑战自己在没有进一步指示的情况下为这个问题编写一个实现。完整的应用程序称为*WordSearch*。如果*k*是给定单词的长度，而板的大小为*m* x *n*，那么此应用程序的运行时间为 O(m * n * 4k)。

## 编码挑战 18 - 根据另一个数组对数组进行排序

**亚马逊**，**谷歌**，**微软**

**问题**：假设你已经得到了两个数组。编写一小段代码，根据第二个数组定义的顺序重新排列第一个数组的元素。

**解决方案**：假设我们已经得到了以下两个数组：

```java
int[] firstArr = {4, 1, 8, 1, 3, 8, 6, 7, 4, 9, 8, 2, 5, 3};
int[] secondArr = {7, 4, 8, 11, 2};
```

预期结果是{7, 4, 4, 8, 8, 8, 2, 1, 1, 3, 3, 5, 6, 9}。

这个问题的解决方案依赖于*哈希*。更确切地说，我们可以采用以下算法：

1.  计算并存储映射中来自第一个数组的每个元素的频率。

1.  对于第二个数组的每个元素，检查当前元素是否存在于映射中。

然后，执行以下操作：

a. 如果是这样，那么在第一个数组中设置*n*次（*n*是第二个数组中当前元素在第一个数组中的频率）。

b. 从映射中删除当前元素，这样最终映射中将只包含在第一个数组中存在但不在第二个数组中的元素。

1.  将映射中的元素追加到第一个数组的末尾（这些元素已经排序，因为我们使用了`TreeSet`）。

让我们看看代码：

```java
public static void custom(int[] firstArr, int[] secondArr) {
  // store the frequency of each element of first array
  // using a TreeMap stores the data sorted
  Map<Integer, Integer> frequencyMap = new TreeMap<>();
  for (int i = 0; i < firstArr.length; i++) {
    frequencyMap.putIfAbsent(firstArr[i], 0);
    frequencyMap.put(firstArr[i],   
          frequencyMap.get(firstArr[i]) + 1);
  }
  // overwrite elements of first array
  int index = 0;
  for (int i = 0; i < secondArr.length; i++) {
    // if the current element is present in the 'frequencyMap'
    // then set it n times (n is the frequency of 
    // that element in the first array)
    int n = frequencyMap.getOrDefault(secondArr[i], 0);
    while (n-- > 0) {
      firstArr[index++] = secondArr[i];
    }
    // remove the element from map
    frequencyMap.remove(secondArr[i]);
  }
  // copy the remaining elements (the elements that are
  // present in the first array but not present 
  // in the second array)        
  for (Map.Entry<Integer, Integer> entry :
        frequencyMap.entrySet()) {
    int count = entry.getValue();
    while (count-- > 0) {
      firstArr[index++] = entry.getKey();
    }
  }
}
```

这段代码的运行时间是 O(m log m + n)，其中*m*是第一个数组中的元素数量，*n*是第二个数组中的元素数量。完整的应用程序称为*SortArrayBasedOnAnotherArray*。

好了，这是本章的最后一个问题。现在，是时候总结我们的工作了！

# 总结

这是一个全面涵盖了排序和搜索算法的章节。您看到了归并排序、快速排序、基数排序、堆排序、桶排序和二分搜索的实现。此外，在本书附带的代码中，还有一个名为*SortArraysIn14Ways*的应用程序，其中包含了 14 种排序算法的实现。

在下一章中，我们将涵盖一系列被归类为数学和谜题问题的问题。


# 第十五章：数学和谜题

本章涵盖了一个在面试中经常遇到的有争议的话题：数学和谜题问题。许多公司认为这类问题不应该成为技术面试的一部分，而其他公司仍然认为这个话题是相关的。

这个话题包括的问题是令人费解的，可能需要相当高的数学和逻辑知识。如果你计划申请在学术领域工作的公司（数学、物理、化学等），你应该期待这样的问题。然而，亚马逊和谷歌等大公司也愿意依赖这类问题。

在本章中，我们将涵盖以下主题：

+   提示和建议

+   编码挑战

在本章结束时，你应该熟悉这类问题，并能够探索更多类似的问题。

# 技术要求

本章中包含的所有代码文件都可以在 GitHub 上找到：[`github.com/PacktPublishing/The-Complete-Coding-Interview-Guide-in-Java/tree/master/Chapter15`](https://github.com/PacktPublishing/The-Complete-Coding-Interview-Guide-in-Java/tree/master/Chapter15)。

# 提示和建议

当你遇到一个脑筋急转弯的问题时，最重要的是不要惊慌。多次阅读问题，并以系统化的方式写下你的结论是必不可少的。必须清楚地确定它应该遵守的输入、输出和约束条件。

尝试举几个例子（输入数据样本），画一些草图，并在分析问题时与面试官保持交流。面试官并不希望你立即得出解决方案，但他们期望听到你在尝试解决问题时的思考过程。这样，面试官可以追踪你的想法逻辑，并了解你解决问题的方式。

此外，非常重要的是写下你在解决问题时注意到的任何规则或模式。每写下一个陈述，你离解决方案更近一步。通常，如果你从解决方案的角度来看（你知道解决方案），这些问题并不是非常困难；它们只是需要高度的观察和更高的注意力。

让我们来试一个简单的例子。两个父亲和两个儿子坐下来吃鸡蛋。他们一共吃了三个鸡蛋；每个人都有一个鸡蛋。这怎么可能？

如果这是你第一次遇到这样的问题，你可能会认为这是不合逻辑或不可能解决的。认为文本中有错误（可能是四个鸡蛋，而不是三个）并一遍又一遍地阅读是正常的。这些是对脑筋急转弯问题最常见的反应。一旦你看到解决方案，它看起来就很简单了。

现在，让我们假设自己是面试官面前的候选人。以下段落采用了*大声思考*的方法。

如果每个人都有一个鸡蛋，而有三个鸡蛋，那么显然有一个人没有鸡蛋。所以，你可能会认为答案是三个人吃了一个鸡蛋（每个人都吃了一个鸡蛋），而第四个人什么都没吃。但问题说两个父亲和两个儿子坐下来吃鸡蛋，所以他们四个人都吃了鸡蛋。

试想一下：每个人都有一个鸡蛋，他们（四个人）一共吃了三个鸡蛋，所以问题并没有说每个人*吃*了一个鸡蛋；他们只是*有*一个鸡蛋。也许其中一个人把自己的鸡蛋分享给了另一个人。嗯，这似乎不太合乎逻辑！

可能只有三个人吗？如果其中一个父亲也是一个祖父，这意味着另一个父亲同时也是一个儿子和父亲。这样，通过三个人，我们有两个父亲和两个儿子。他们吃了三个鸡蛋，每个人都有一个鸡蛋。问题解决了！

正如你所看到的，解决方案是通过一系列推理的结果，逐个排除错误的解决方案而得到的。试图通过逻辑推理排除错误的解决方案来解决问题是解决这类问题的方法之一。其他问题只是关于计算。大多数时候，没有复杂的计算或大量的计算，但它们需要数学知识和/或推理。

很难断言有一些技巧和提示可以帮助你在几秒钟内解决数学和逻辑谜题问题。最好的方法是尽可能多地练习。有了这个，让我们继续进行*编码挑战*部分。

# 编码挑战

在接下来的 15 个编码挑战中，我们将专注于数学和逻辑谜题类别中最受欢迎的问题。让我们开始吧！

## 编码挑战 1 - FizzBuzz

**Adobe**，**Microsoft**

**问题**：考虑到你已经得到了一个正整数*n*。编写一个问题，打印从 1 到*n*的数字。对于 5 的倍数，打印*fizz*，对于 7 的倍数，打印*buzz*，对于 5 和 7 的倍数，打印*fizzbuzz*。在每个字符串或数字后打印一个新行。

**解决方案**：这是一个简单的问题，依赖于你对除法和 Java 取模(%)运算符的了解。当我们除两个数，被除数和除数，我们得到一个商和一个余数。在 Java 中，我们可以通过取模(%)运算符获得除法的余数。换句话说，如果*X*是被除数，*Y*是除数，那么*X*模*Y*（在 Java 中写作*X* % *Y*）返回*X*除以*Y*的余数。例如，11(被除数) / 2(除数) = 5(商) 1(余数)，所以 11 % 2 = 1。

换句话说，如果余数为 0，则被除数是除数的倍数；否则，它不是。因此，五的倍数必须满足*X* % 5 = 0，而七的倍数必须满足*X* % 7 = 0。基于这些关系，我们可以将这个问题的解决方案写成如下形式：

```java
public static void print(int n) {
  for (int i = 1; i <= n; i++) {
    if (((i % 5) == 0) && ((i % 7) == 0)) { // multiple of 5&7            
      System.out.println("fizzbuzz");
    } else if ((i % 5) == 0) { // multiple of 5            
      System.out.println("fizz");
    } else if ((i % 7) == 0) { // multiple of 7            
      System.out.println("buzz");
    } else {
      System.out.println(i); // not a multiple of 5 or 7
    }
  }
}
```

完整的应用程序称为*FizzBuzz*。

## 编码挑战 2 - 罗马数字

**Amazon**，**Google**，**Adobe**，**Microsoft**，**Flipkart**

**问题**：考虑到你已经得到了一个正整数*n*。编写一小段代码，将这个数字转换成它的罗马数字表示。例如，如果*n*=34，那么罗马数字就是 XXXIV。你已经得到了以下包含罗马数字符号的常量：

![图 15.1 - 罗马数字](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_15.1_B15403.jpg)

图 15.1 - 罗马数字

**解决方案**：这个问题依赖于罗马数字是常识。如果你从来没有听说过罗马数字，那么最好向面试官提到这一点。他们可能会同意给你另一个编码挑战来代替这个。但如果你知道罗马数字是什么，那太好了 - 让我们看看如何编写一个解决这个问题的应用程序。

这个问题的算法可以从几个例子中推导出来。让我们看几个用例：

+   *n* = 73 = 50+10+10+1+1+1 = L+X+X+I+I+I = LXXIII

+   *n* = 558 = 500+50+5+1+1+1 = D+L+V+I+I+I = DLVIII

+   *n* = 145 = 100+(50-10)+5 = C+(L-X)+V = C+XL+V = CXLV

+   *n* = 34 = 10+10+10+(5-1) = X+X+X+(V-I) = X+X+X+IV = XXXIV

+   *n* = 49 = (50-10)+(10-1) = (L-X)+(X-I) = XL+IX = XLIX

大致上，我们拿到给定的数字，然后尝试找到对应于个位、十位、百位或千位的罗马符号。这个算法可以表达如下：

1.  从千位开始并打印相应的罗马数字。例如，如果千位上的数字是 4，则打印 4000 的罗马数字等价物，即 MMMM。

1.  继续通过使用百位数字分割数字并打印相应的罗马数字。

1.  继续通过使用十位数字分割数字并打印相应的罗马数字。

1.  继续通过使用个位数对数字进行除法，并打印相应的罗马数字。

在代码方面，这个算法的工作原理如下：

```java
private static final String HUNDREDTHS[]
 = {"", "C", "CC", "CCC", "CD", "D", 
    "DC", "DCC", "DCCC", "CM"};
private static final String TENS[]
 = {"", "X", "XX", "XXX", 
    "XL", "L", "LX", "LXX", "LXXX", "XC"};
private static final String ONES[]
 = {"", "I", "II", "III", "IV", "V", 
    "VI", "VII", "VIII", "IX"};
public static String convert(int n) {
  String roman = "";
  // Step 1
  while (n >= 1000) {
    roman = roman + 'M';
    n -= 1000;
  }
  // Step 2
  roman = roman + HUNDREDTHS[n / 100];
  n = n % 100;
  // Step 3
  roman = roman + TENS[n / 10];
  n = n % 10;
  // Step 4
  roman = roman + ONES[n];
  return roman;
}
```

完整的应用程序称为*RomanNumbers*。另一种方法依赖于连续的减法而不是除法。*RomanNumbers*应用程序也包含了这种实现。

## 编码挑战 3 - 访问和切换 100 扇门

**Adobe**，**Microsoft**，**Flipkart**

**问题**：假设你有 100 扇门，它们最初都是关闭的。你必须访问这些门 100 次，每次都从第一扇门开始。对于每个访问的门，你都要切换它（如果它关闭，则打开它，反之亦然）。在第一次访问时，你访问所有 100 扇门。在第二次访问时，你访问每第二扇门（＃2、＃4、＃6……）。在第三次访问时，你访问每第三扇门（＃3、＃6、＃9……）。你按照这个模式一直到只访问第 100 扇门。编写一小段代码，揭示 100 次访问后门的状态（关闭或打开）。

**解决方案**：通过遍历几步可以直观地解决这个问题。在初始状态下，所有 100 扇门都是关闭的（在下图中，每个 0 都是关闭的门，每个 1 都是打开的门）：

![图 15.2 - 所有门都关闭（初始状态）](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_15.2_B15403.jpg)

图 15.2 - 所有门都关闭（初始状态）

现在，让我们看看在以下每个步骤中我们能观察和得出什么结论：

在第一次访问时，我们打开每扇门（我们访问每扇门，＃1、＃2、＃3、＃4、…，＃100）：

![图 15.3 - 所有门都打开（步骤 1）](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_15.3_B15403.jpg)

图 15.3 - 所有门都打开（步骤 1）

在第二次访问时，我们只访问偶数门（＃2、＃4、＃6、＃8、＃10、＃12……），所以偶数门关闭，奇数门打开：

![图 15.4 - 偶数门关闭，奇数门打开（步骤 2）](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_15.4_B15403.jpg)

图 15.4 - 偶数门关闭，奇数门打开（步骤 2）

在第三次访问时，我们只访问门＃3、＃6、＃9、＃12……这次，我们关闭了第一次访问时打开的门＃3，打开了第二次访问时关闭的门＃6，依此类推：

![图 15.5 - 应用第三次访问后的结果（步骤 3）](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_15.5_B15403.jpg)

图 15.5 - 应用第三次访问后的结果（步骤 3）

在第四次访问时，我们只访问门＃4、＃8、＃12……如果我们继续这样做，那么在第 100 次访问时，我们将得到以下结果：

![图 15.6 - 所有打开的门都是完全平方数（最后一次访问）](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_15.6_B15403.jpg)

图 15.6 - 所有打开的门都是完全平方数（最后一次访问）

因此，在最后一次访问（第 100 次访问）时，所有打开的门都是完全平方数，而其余的门都是关闭的。显然，即使我们观察到这一点，在面试中我们也没有足够的时间来遍历 100 次访问。但也许我们甚至不需要做所有 100 次访问来观察这个结果。让我们假设我们只做 15 步，然后我们试图看看某扇门发生了什么。例如，以下图像显示了门＃12 在 15 步中的状态：

![图 15.7 - 第 15 步后的门＃12](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_15.7_B15403.jpg)

图 15.7 - 第 15 步后的门＃12

检查前面图像中突出显示的步骤。门＃12 的状态在*步骤 1、2、3、4、6*和*12*发生了变化。所有这些步骤都是 12 的约数。此外，*步骤 1*打开门，*步骤 2*关闭门，*步骤 3*打开门，*步骤 4*关闭门，*步骤 6*打开门，*步骤 12*关闭门。从这个观察开始，我们可以得出结论，对于每一对约数，门最终都会回到初始状态，即关闭状态。换句话说，每个具有偶数个约数的门最终都会关闭。

让我们看看这是否对于一个完全平方数来说是正确的，比如 9。选择完全平方数的原因在于完全平方数总是有奇数个正因子。例如，9 的因子是 1、3 和 9。这意味着门#9 保持打开状态。

根据这两段文字，我们可以得出结论，经过 100 次访问后，保持打开状态的门是那些完全平方数（#1，#4，#9，#16，...，#100），而其余的门保持关闭状态。

一旦你理解了前面的过程，编写一个确认最终结果的应用程序就非常简单了：

```java
private static final int DOORS = 100;
public static int[] visitToggle() {
  // 0 - closed door
  // 1 - opened door     
  int[] doors = new int[DOORS];
  for (int i = 0; i <= (DOORS - 1); i++) {
    doors[i] = 0;
  }
  for (int i = 0; i <= (DOORS - 1); i++) {
    for (int j = 0; j <= (DOORS - 1); j++) {
      if ((j + 1) % (i + 1) == 0) {
        if (doors[j] == 0) {
          doors[j] = 1;
        } else {
          doors[j] = 0;
        }
      }
    }            
  }
  return doors;
}
```

完整的应用程序称为*VisitToggle100Doors*。

## 编码挑战 4 - 8 支队伍

**亚马逊**，**谷歌**，**Adobe**

**问题**：考虑有一个比赛，有 8 支队伍。每支队伍与其他队伍比赛两次。从所有这些队伍中，只有 4 支队伍进入半决赛。一支队伍要赢得多少场比赛才能进入半决赛？

**解决方案**：让我们将队伍标记为 T1、T2、T3、T4、T5、T6、T7 和 T8。如果 T1 与 T2...T8 比赛，他们将进行 7 场比赛。由于每个队伍必须与其他队伍比赛两次，所以我们有 8*7=56 场比赛。如果每场比赛中一支队伍可以赢得一分，那么我们有 56 分分配给 8 支队伍。

让我们考虑最坏的情况。T0 输掉了所有比赛。这意味着 T0 得到 0 分。另一方面，T1 对 T0 赢得了 2 分，并输掉了所有其他比赛，T2 对 T0 和 T1 赢得了 4 分，并输掉了所有其他比赛，T3 对 T0、T1 和 T2 赢得了 6 分，并输掉了所有其他比赛，依此类推。T4 赢得了 8 分，T5 赢得了 10 分，T6 赢得了 12 分，T7 赢得了 14 分。因此，一支赢得所有比赛的队伍赢得了 14 分。最后四支队伍（进入半决赛的队伍）赢得了 8+10+12+14=44 分。因此，一支队伍可以确保他们进入半决赛，如果他们获得至少 44/4=11 分。

## 编码挑战 5 - 找到具有质因数 3、5 和 7 的第 k 个数字

**Adobe**，**微软**

**问题**：设计一个算法，找到唯一的质因数是 3、5 和 7 的第 k 个数字。

**解决方案**：拥有一组数字，其唯一的质因数是 3、5 和 7，意味着一组看起来如下：1、3、5、7、9、15、21、25 等等。或者，更具启发性地，可以写成：1、1*3、1*5、1*7、3*3、3*5、3*7、5*5、3*3*3、5*7、3*3*5、7*7 等等。

通过这种具有启发性的表示，我们可以看到我们可以最初将值 1 插入列表中，而其余的元素必须计算出来。理解确定其余元素的算法最简单的方法是看实现本身，所以让我们来看看：

```java
public static int kth(int k) {
  int count3 = 0;
  int count5 = 0;
  int count7 = 0;
  List<Integer> list = new ArrayList<>();
  list.add(1);
  while (list.size() <= k + 1) {
    int m = min(min(list.get(count3) * 3, 
      list.get(count5) * 5), list.get(count7) * 7);
    list.add(m);
    if (m == list.get(count3) * 3) {
      count3++;
    }
    if (m == list.get(count5) * 5) {
      count5++;
    }
    if (m == list.get(count7) * 7) {
      count7++;
    }
  }
  return list.get(k - 1);
}
```

我们也可以通过三个队列来实现。该算法的步骤如下：

1.  初始化一个整数*minElem*=1。

1.  初始化三个队列；即*queue3*、*queue5*和*queue7*。

1.  从 1 到给定的*k*-1 进行循环：

a. 将*minElem**3、*minElem**5 和*minElem**7 分别插入*queue3*、*queue5*和*queue7*。

b. 更新*minElem*为 min(*queue3*.peek, *queue5*.peek, *queue7*.peek)。

c. 如果*minElem*是*queue3*.peek，则执行*queue3*.poll。

d. 如果*minElem*是*queue5*.peek，则执行*queue5*.poll。

e. 如果*minElem*是*queue7*.peek，则执行*queue7*.poll。

1.  返回*minElem*。

完整的应用程序称为*KthNumber357*。它包含了本节中提出的两种解决方案。

## 编码挑战 6 - 计算解码数字序列

**亚马逊**，**微软**，**Flipkart**

**问题**：假设*A*是 1，*B*是 2，*C*是 3，... *Z*是 26。对于任何给定的数字序列，编写一小段代码来计算可能的解码数量（例如，1234 可以解码为 1 2 3 4，12 3 4 和 1 23 4，也就是 ABCD、LCD 和 AWD）。如果给定的数字序列包含从 0 到 9 的数字，则它是有效的。不允许前导 0，不允许额外的尾随 0，也不允许连续出现两个或更多个 0。

**解决方案**：这个问题可以通过递归或动态规划来解决。这两种技术都在*第八章**，递归和动态规划*中讨论过。因此，让我们看看一个 *n* 位数字序列的递归算法：

1.  将解码的总数初始化为 0。

1.  从给定数字序列的末尾开始。

1.  如果最后一位不是 0，则对(*n*-1)位数字应用递归，并使用结果更新解码的总数。

1.  如果最后两位数字表示的数字小于 27（因此是有效字符），则对(*n*-2)位数字应用递归，并使用结果更新解码的总数。

在代码方面，我们有以下内容：

```java
public static int decoding(char[] digits, int n) {
  // base cases 
  if (n == 0 || n == 1) {
    return 1;
  }
  // if the digits[] starts with 0 (for example, '0212')
  if (digits == null || digits[0] == '0') {
    return 0;
  }
  int count = 0;
  // If the last digit is not 0 then last 
  // digit must add to the number of words 
  if (digits[n - 1] > '0') {
    count = decoding(digits, n - 1);
  }
  // If the last two digits represents a number smaller 
  // than or equal to 26 then consider last two digits 
  // and call decoding()
  if (digits[n - 2] == '1'
      || (digits[n - 2] == '2' && digits[n - 1] < '7')) {
    count += decoding(digits, n - 2);
  }
  return count;
}
```

这段代码运行时间是指数级的。但是我们可以应用动态规划，通过类似的非递归算法将运行时间降低到 O(n)，具体如下：

```java
public static int decoding(char digits[]) {
  // if the digits[] starts with 0 (for example, '0212')
  if (digits == null || digits[0] == '0') {
    return 0;
  }
  int n = digits.length;
  // store results of sub-problems 
  int count[] = new int[n + 1];
  count[0] = 1;
  count[1] = 1;
  for (int i = 2; i <= n; i++) {
    count[i] = 0;
    // If the last digit is not 0 then last digit must 
    // add to the number of words 
    if (digits[i - 1] > '0') {
      count[i] = count[i - 1];
    }
    // If the second last digit is smaller than 2 and 
    // the last digit is smaller than 7, then last 
    // two digits represent a valid character 
    if (digits[i - 2] == '1' || (digits[i - 2] == '2' 
          && digits[i - 1] < '7')) {
      count[i] += count[i - 2];
    }
  }
  return count[n];
}
```

这段代码运行时间是 O(n)。完整的应用程序称为 *DecodingDigitSequence*。

## 编程挑战 7 – ABCD

**问题**：找到一种类型的数字 ABCD，使得乘以 4 后得到 DCBA。

**解决方案**：这类问题通常相当难。在这种情况下，我们必须使用一些数学来解决它。

让我们从一些简单的不等式开始：

+   1 <= A <= 9（A 不能为零，因为 ABCD 是一个四位数）

+   0 <= B <= 9

+   0 <= C <= 9

+   4 <= D <= 9（D 必须至少为 4*A，所以至少应为 4）

接下来，我们可以假设我们的数字 ABCD 被写成 1000A + 100B + 10C + D。根据问题描述，我们可以将 ABCD 乘以 4 得到 DCBA，可以写成 1000D + 100C + 10B + A。

符合 4 的整除性，BA 是一个可以被 4 整除的两位数。现在，较大的 ABCD 是 2499，因为大于 2499 的数乘以 4 将得到一个五位数。

接下来，A 可以是 1 和 2。然而，如果 BA 是一个可以被 4 整除的两位数，那么 A 必须是偶数，所以必须是 2。

继续这种逻辑，这意味着 D 要么是 8，要么是 9。然而，由于 D 乘以 4 会以 2 结尾，所以 D 必须是 8。

此外，4000A + 400B + 40C + 4D = 1000D + 100C + 10B + A。由于 A=2 和 D=8，这可以写成 2C-13B=1。B 和 C 只能是 [1, 7] 范围内的个位整数，但由于 BA 是一个可以被 4 整除的两位数，B 必须是奇数。由于最大可能的数字是 2499，这意味着 B 可以是 1 或 3。

因此，结果是 2178，因为 2178*4=8712，所以 ABCD*4=DCBA。

我们也可以使用蛮力方法来找到这个数字。以下代码说明了这一点：

```java
public static void find() {
  for (int i = 1000; i < 2499; i++) {
    int p = i;
    int q = i * 4;
    String m = String.valueOf(p);
    String n = new StringBuilder(String.valueOf(q))
      .reverse().toString();
    p = Integer.parseInt(m);
    q = Integer.parseInt(n);
    if (p == q) {
      System.out.println("\n\nFound: " + p + " : " + (q * 4));
      break;
    }
  }
}
```

完整的应用程序称为 *Abcd*。

## 编程挑战 8 – 重叠的矩形

**亚马逊**，**谷歌**，**微软**

`true` 如果这些矩形重叠（也称为相交）。

**解决方案**：这个问题听起来有点模糊。重要的是要与面试官讨论并就两个重要方面达成一致：

*这两个矩形是平行的，并且与水平面成 0 度角（它们与坐标轴平行），或者它们可以在一个角度下旋转吗？*

大多数情况下，给定的矩形是平行的，并且与坐标轴平行。如果涉及旋转，那么解决方案需要一些几何知识，这在面试中并不那么明显。面试官很可能是想测试你的逻辑，而不是你的几何知识，但是挑战自己，为非平行矩形实现问题。

*矩形的坐标是在笛卡尔平面上给出的吗？* 答案应该是肯定的，因为这是数学中常用的坐标系。这意味着一个矩形从左到右，从下到上增加大小。

因此，让我们将矩形表示为*r1*和*r2*。它们每个都是通过左上角和右下角的坐标给出的。*r1*的左上角的坐标为*r1lt.x*和*r1lt.y*，而右下角的坐标为*r2rb.x*和*r2rb.y*，如下图所示：

![图 15.8-矩形坐标](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_15.8_B15403.jpg)

图 15.8-矩形坐标

我们可以说，如果两个矩形*接触*（至少有一个公共点），它们就是重叠的。换句话说，在下图中显示的五对矩形中，有重叠：

![图 15.9-重叠的矩形](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_15.9_B15403.jpg)

图 15.9-重叠的矩形

从前面的图表中，我们可以得出两个不重叠的矩形可能处于以下四种情况之一：

+   *r1*完全在*r2*的右边。

+   *r1*完全在*r2*的左边。 

+   *r1*完全在*r2*的上方。

+   *r1*完全在*r2*下方。

以下图表显示了这四种情况：

![图 15.10-不重叠的矩形](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_15.10_B15403.jpg)

图 15.10-不重叠的矩形

我们可以用坐标表示前面的四个项目，如下所示：

+   *r1*完全在*r2*的右边→*r1lt.x>r2rb.x*

+   *r1*完全在*r2*的左边→*r2lt.x>r1rb.x*

+   *r1*完全在*r2*上方→*r1rb.y>r2lt.y*

+   *r1*完全在*r2*下方→*r2rb.y>r1lt.y*

因此，如果我们将这些条件分组到代码中，我们得到以下结果：

```java
public static boolean overlap(Point r1lt, Point r1rb, 
        Point r2lt, Point r2rb) {
  // r1 is totally to the right of r2 or vice versa
  if (r1lt.x > r2rb.x || r2lt.x > r1rb.x) {
    return false;
  }
  // r1 is totally above r2 or vice versa
  if (r1rb.y > r2lt.y || r2rb.y > r1lt.y) {
    return false;
  }
  return true;
}
```

这段代码运行时间为 O(1)。或者，我们可以将这两个条件合并为一个条件，如下所示：

```java
public static boolean overlap(Point r1lt, Point r1rb, 
        Point r2lt, Point r2rb) {
  return (r1lt.x <= r2rb.x && r1rb.x >= r2lt.x
           && r1lt.y >= r2rb.y && r1rb.y <= r2lt.y);
}
```

完整的应用程序称为*RectangleOverlap*。请注意，面试官可能以不同的方式定义*重叠*。根据这个问题，你应该能够相应地调整代码。

## 编码挑战 9-乘以大数

**亚马逊**，**微软**

整数或长整数域。编写一个计算*a*b*的代码片段。

**解决方案**：让我们假设*a*=4145775 和*b*=771467。然后，*a*b*=3198328601925。解决这个问题依赖于数学。以下图像描述了可以在纸上应用并编码的*a*b*解决方案：

![图 15.11-两个大数相乘](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_15.11_B15403.jpg)

图 15.11-两个大数相乘

主要是，我们依赖于乘法可以写成一系列加法的事实。因此，我们可以将 771467 写成 7+60+400+1000+70000+700000，然后我们将这些数字中的每一个与 4145775 相乘。最后，我们将结果相加以获得最终结果 3198328601925。进一步推理，我们可以取第一个数字的最后一位（5）并将其乘以第二个数字的所有数字（7,6,4,1,7,7）。然后，我们取第一个数字的第二位（7）并将其乘以第二个数字的所有数字（7,6,4,1,7,7）。然后，我们取第一个数字的第三位（7）并将其乘以第二个数字的所有数字（7,6,4,1,7,7）。我们继续这个过程，直到我们将第一个数字的所有数字乘以第二个数字的所有数字。在添加结果时，我们声明*t*th 乘法移位。

在代码方面，我们有以下内容：

```java
public static String multiply(String a, String b) {
  int lenA = a.length();
  int lenB = b.length();
  if (lenA == 0 || lenB == 0) {
    return "0";
  }
  // the result of multiplication is stored in reverse order 
  int c[] = new int[lenA + lenB];
  // indexes to find positions in result
  int idx1 = 0;
  int idx2 = 0;
  // loop 'a' right to left
  for (int i = lenA - 1; i >= 0; i--) {
    int carry = 0;
    int n1 = a.charAt(i) - '0';
    // used to shift position to left after every 
    // multiplication of a digit in 'b' 
    idx2 = 0;
    // loop 'b' from right to left
    for (int j = lenB - 1; j >= 0; j--) {
      // current digit of second number 
      int n2 = b.charAt(j) - '0';
      // multiply with current digit of first number 
      int sum = n1 * n2 + c[idx1 + idx2] + carry;
      // carry of the next iteration
      carry = sum / 10;
      c[idx1 + idx2] = sum % 10;
      idx2++;
    }
    // store carry 
    if (carry > 0) {
      c[idx1 + idx2] += carry;
    }
    // shift position to left after every 
    // multiplication of a digit in 'a' 
    idx1++;
  }
  // ignore '0's from the right 
  int i = c.length - 1;
  while (i >= 0 && c[i] == 0) {
    i--;
  }
  // If all were '0's - means either both or 
  // one of 'a' or 'b' were '0' 
  if (i == -1) {
    return "0";
  }
  String result = "";
  while (i >= 0) {
    result += (c[i--]);
  }
  return result;
}
```

完整的应用程序称为*MultiplyLargeNumbers*。

## 编码挑战 10-具有相同数字的下一个最大数字

**亚马逊**，**谷歌**，**微软**

**问题**：考虑到你已经得到了一个正整数。编写一个返回具有相同数字的下一个最大数字的代码片段。

**解决方案**：通过几个示例可以观察到这个问题的解决方案。让我们考虑以下示例：

+   示例 1：6→不可能

+   示例 2：1234→1243

+   示例 3：1232→1322

+   示例 4：321→不可能

+   示例 5：621873→623178

从前面的例子中，我们可以直觉到解决方案可以通过重新排列给定数字的数字来获得。因此，如果我们可以找到交换数字的规则集，使我们得到要搜索的数字，那么我们可以尝试实现。

让我们尝试几个观察：

+   从示例 1 和 4 可以看出，如果给定数字的数字是降序的，那么不可能找到更大的数字。每次交换都会导致更小的数字。

+   从示例 2 可以看出，如果给定数字的数字是按升序排列的，那么具有相同数字的下一个更大数字可以通过交换最后两个数字来获得。

+   从示例 3 和 5 可以看出，我们需要找到所有更大数字中的最小数字。为此，我们必须从最右边处理数字。以下算法阐明了这一说法。

基于这三点观察，我们可以详细说明以下算法，该算法已在数字 621873 上进行了示例：

1.  我们从最右边的数字开始逐个遍历数字。我们一直遍历，直到找到一个比先前遍历的数字小的数字。例如，如果给定的数字是 621873，那么我们遍历到 621873 中的数字 1。数字 1 是第一个比先前遍历的数字 8 小的数字。

1.  接下来，我们关注我们在步骤 1 中找到的数字右侧的数字。我们想在这些数字中找到最小的数字（我们将其表示为*t*）。由于这些数字按降序排列，最小的数字在最后位置。例如，3 是 1 右侧数字中最小的数字，62**1**87**3**。

1.  我们交换这两个数字（1 和 3），我们得到 62**3**87**1**。

1.  最后，我们将所有数字按升序排列到*t*的右侧。但是由于我们知道*t*右侧的所有数字都是按降序排列的，除了最后一个数字，我们可以应用线性反转。这意味着结果是 623**178**。这就是要搜索的数字。

这个算法可以很容易地实现，如下所示：

```java
public static void findNextGreater(int arr[]) {
  int min = -1;
  int len = arr.length;
  int prevDigit = arr[arr.length - 1];
  int currentDigit;
  // Step 1: Start from the rightmost digit and find the 
  // first digit that is smaller than the digit next to it. 
  for (int i = len - 2; i >= 0; i--) {
    currentDigit = arr[i];
    if (currentDigit < prevDigit) {
      min = i;
      break;
    }
  }
  // If 'min' is -1 then there is no such digit. 
  // This means that the digits are in descending order. 
  // There is no greater number with same set of digits 
  // as the given one.
  if (min == -1) {
    System.out.println("There is no greater number with "
     + "same set of digits as the given one.");
  } else {
    // Steps 2 and 3: Swap 'min' with 'len-1'
    swap(arr, min, len - 1);
    // Step 4: Sort in ascending order all the digits 
    // to the right side of the swapped 'len-1'
    reverse(arr, min + 1, len - 1);
    // print the result
    System.out.print("The next greater number is: ");
    for (int i : arr) {
      System.out.print(i);
    }
  }
}
private static void reverse(int[] arr, int start, int end) {
  while (start < end) {
    swap(arr, start, end);
    start++;
    end--;
  }
}
private static void swap(int[] arr, int i, int j) {
  int aux = arr[i];
  arr[i] = arr[j];
  arr[j] = aux;
}
```

这段代码运行时间为 O(n)。完整的应用程序称为*NextElementSameDigits*。

## 编码挑战 11 - 数字可被其数字整除

**亚马逊**，**谷歌**，**Adobe**，**微软**

如果给定数字可以被其数字整除，则返回`true`。

`true`，因为 412 可以被 2、1 和 4 整除。另一方面，如果*n*=143，那么输出应该是`false`，因为 143 不能被 3 和 4 整除。

如果你认为这个问题很简单，那么你是完全正确的。这些问题被用作*热身*问题，并且有助于快速筛选出很多候选人。大多数情况下，你应该在规定的时间内解决它（例如，2-3 分钟）。

重要说明

建议对待这些简单的问题与对待任何其他问题一样认真。一个小错误可能会让你提前退出比赛。

因此，对于这个问题，算法包括以下步骤：

1.  获取给定数字的所有数字。

1.  对于每个数字，检查*给定数字* *%数字*是否为 0（这意味着可被整除）。

1.  如果其中任何一个不为零，则返回`false`。

1.  如果对于所有数字，*给定数字%数字*都是 0，则返回`true`。

在代码方面，我们有以下内容：

```java
public static boolean isDivisible(int n) {
  int t = n;
  while (n > 0) {
    int k = n % 10;
    if (k != 0 && t % k != 0) {
      return false;
    }
    n /= 10;
  }
  return true;
}
```

完整的应用程序称为*NumberDivisibleDigits*。

## 编码挑战 12 - 打破巧克力

**亚马逊**，**谷歌**，**Adobe**，**微软**，**Flipkart**

**问题**：考虑到你已经得到了尺寸为*宽度* x *高度*的矩形巧克力条和一些瓷砖。通常情况下，巧克力由许多小瓷砖组成，因此*宽度*和*高度*给出了我们的瓷砖数量（例如，巧克力尺寸为 4 x 3，包含 12 块瓷砖）。编写一小段代码，计算我们需要对给定的巧克力施加多少次断裂（切割）才能获得具有完全所需数量的瓷砖的一块。您可以通过单个垂直或水平断裂（切割）将给定的巧克力切成两个矩形块。

**解决方案**：让我们考虑以下图像中显示的巧克力（一个 3 x 6 的巧克力条，有 18 块瓷砖）：

![图 15.12 – 一个 3 x 6 巧克力条](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_15.12_B15403.jpg)

图 15.12 – 一个 3 x 6 巧克力条

前面的图像显示了七种情况，可以带我们找到解决方案，如下：

+   情况 1、2 和 3：如果给定瓷砖的数量大于 3 x 6 或者我们无法将瓷砖与巧克力的*宽度*或*高度*排列在一起，则无法获得解决方案。对于无解，我们返回-1。

+   情况 4：如果给定瓷砖的数量等于 3 x 6 = 18，则这就是解决方案，所以我们不需要切割。我们将返回 0。

+   情况 5：如果给定瓷砖的数量可以与巧克力条的*宽度*排列在一起，则只需要一次切割。我们将返回 1。

+   情况 6：如果给定瓷砖的数量可以与巧克力条的*高度*排列在一起，则只需要一次切割。我们将返回 1。

+   情况 7：在所有其他情况下，我们需要 2 次切割。我们将返回 2。

让我们看看代码：

```java
public static int breakit(int width, int height, int nTiles) {
  if (width <= 0 || height <= 0 || nTiles <= 0) {
    return -1;
  }
  // case 1
  if (width * height < nTiles) {
    return -1;
  }
  // case 4
  if (width * height == nTiles) {
    return 0;
  } 
  // cases 5 and 6
  if ((nTiles % width == 0 && (nTiles / width) < height)
     || (nTiles % height == 0 && (nTiles / height) < width)) {
    return 1;
  }
  // case 7
  for (int i = 1; i <= Math.sqrt(nTiles); i++) {
    if (nTiles % i == 0) {
      int a = i;
      int b = nTiles / i;
      if ((a <= width && b <= height)
          || (a <= height && b <= width)) {
        return 2;
      }
    }
  }
  // cases 2 and 3
  return -1;
}
```

完整的应用程序称为*BreakChocolate*。

## 编码挑战 13 – 时钟角度

**谷歌**，**微软**

**问题**：考虑到你已经以*h:m*格式给出时间。编写一小段代码，计算模拟时钟上时针和分针之间的较短角度。

**解决方案**：从一开始，我们必须考虑几个公式，这些公式将帮助我们得出解决方案。

首先，时钟被分成 12 个相等的小时（或 12 个相等的部分），因为它是一个完整的圆，所以有 360o。因此，1 小时有 360o/12 = 30o。因此，在 1:00 时，时针与分针形成 300 的角度。在 2:00 时，时针与分针形成 60o 的角度，依此类推。以下图像阐明了这一方面：

![图 15.13 – 12 小时的 360 度分割](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_15.13_B15403.jpg)

图 15.13 – 12 小时的 360 度分割

进一步推理，1 小时有 60 分钟和 30o，因此 1 分钟有 30/60 = 0.5o。因此，如果我们只参考时针，那么在 1:10 时，我们有 30o + 10*0.5o = 30o + 5o = 35o。或者，在 4:17 时，我们有 4*30o + 17*0.5o = 120o + 8.5o = 128.5o。

到目前为止，我们知道可以计算给定*h:m*时间的时针角度为*h**300 + *m**0.5o。对于计算分针的角度，我们可以认为，在 1 小时内，分针需要完成 360o 的旋转，因此 360o/ 60 分钟 = 每分钟 6o。因此，在*h*:24 时，分针形成 144o 的角度。在*h*:35 时，分针形成 210o 的角度，依此类推。

因此，时针和分针之间的角度是 abs((*h**30o + *m**0.5o) - *m**6o)。如果返回的*result*大于 180o，则我们必须返回(360o - *result*)，因为问题要求我们计算时针和分针之间的较短角度。

现在，让我们尝试计算以下图像中显示的时钟所需的角度：

![图 15.14 – 三个时钟](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_15.14_B15403.jpg)

图 15.14 – 三个时钟

**时钟 1，10:10**：

+   时针：10*30o + 10*0.5o = 300o + 5o = 305o

+   分针：10 * 6o = 60o

+   结果：abs(305o - 60o) = abs(245o) = 245o > 180o，因此返回 360o - 245o = 115o

**时钟 2，9:40**：

+   时针：9*30o + 40*0.5o = 270o + 20o = 290o

+   分针：40 * 6o = 240o

+   结果：abs(290o - 240o) = abs(50o) = 50o

**时钟 3，4:40**：

+   时针：4*30o + 40*0.5o = 120o + 20o = 140o

+   分钟：40 * 6o = 240o

+   结果：abs(140o - 240o) = abs(-100o) = 100o

根据这些陈述，我们可以编写以下代码：

```java
public static float findAngle(int hour, int min) {
  float angle = (float) Math.abs(((30f * hour) 
    + (0.5f * min)) - (6f * min));
  return angle > 180f ? (360f - angle) : angle;
}
```

完整的应用程序称为*HourMinuteAngle*。

## 编码挑战 14-勾股定理三元组

**谷歌**，**Adobe**，**微软**

**问题**：勾股定理三元组是一组三个正整数{*a，b，c*}，使得*a*2 = *b*2 + *c*2。假设你得到了一个正整数数组*arr*。编写一小段代码，打印出这个数组的所有勾股定理三元组。

**解决方案**：可以通过三个循环实现蛮力方法，尝试给定数组中的所有可能三元组。但这将在 O(n3)的复杂度时间内工作。显然，蛮力方法（通常称为*naive*方法）不会给面试官留下深刻印象，所以我们必须做得比这更好。

实际上，我们可以在 O(n2)的时间内解决这个问题。让我们看看算法的步骤：

1.  对输入数组中的每个元素进行平方（O(n)）。这意味着我们可以将*a*2 = *b*2 + *c*2 写成*a* = *b* + *c*。

1.  按升序对给定数组进行排序（O(n log n)）。

1.  如果*a* = *b* + *c*，那么*a*始终是*a*、*b*和*c*之间的最大值。因此，我们固定*a*，使其成为这个排序数组的最后一个元素。

1.  固定*b*，使其成为这个排序数组的第一个元素。

1.  固定*c*，使其成为元素*a*之前的元素。

1.  到目前为止，*b<a*且*c<a*。要找到勾股定理三元组，执行一个循环，从 1 增加*b*到*n*，从*n*减少*c*到 1。当*b*和*c*相遇时，循环停止：

a. 如果*b + c < a*，则增加*b*的索引。

b. 如果*b + c > a*，则减少*c*的索引。

c. 如果*b + c*等于*a*，则打印找到的三元组。增加*b*的索引并减少*c*的索引。

1.  从*步骤 3*开始重复下一个*a*。

假设*arr*={3, 6, 8, 5, 10, 4, 12, 14}。经过前两步，*arr*={9, 16, 25, 36, 64, 100, 144, 196}。经过*步骤 3*、*4*和*5*，我们有*a*=196，*b*=9，*c*=144，如下所示：

![图 15.15-设置 a、b 和 c](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_15.15_B15403.jpg)

图 15.15-设置 a、b 和 c

由于 9+144 < 196，*b*的索引增加 1，符合*步骤 6a*。对于 16+144，25+144 和 36+144，同样的步骤适用。由于 64+144 > 196，*c*的索引减少 1，符合*步骤 6b*。

由于 64 +100 < 196，*b*的索引增加 1，符合*步骤 6a*。循环在这里停止，因为*b*和*c*相遇，如下所示：

![图 15.16-循环结束时的 b 和 c](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_15.16_B15403.jpg)

图 15.16-循环结束时的 b 和 c

接下来，根据*步骤 7*，我们设置*a*=144，*b*=9，*c*=100。对每个*a*重复此过程。当*a*变为 100 时，我们找到了第一个勾股定理三元组；即*a*=100，*b*=36，*c*=64，如下所示：

![图 15.17-勾股定理三元组](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_15.17_B15403.jpg)

图 15.17-勾股定理三元组

让我们把这个算法写成代码：

```java
public static void triplet(int arr[]) {
  int len = arr.length;
  // Step1
  for (int i = 0; i < len; i++) {
    arr[i] = arr[i] * arr[i];
  }
  // Step 2
  Arrays.sort(arr);
  // Steps 3, 4, and 5
  for (int i = len - 1; i >= 2; i--) {  
    int b = 0;
    int c = i - 1;
    // Step 6
    while (b < c) {
      // Step 6c
      if (arr[b] + arr[c] == arr[i]) {
        System.out.println("Triplet: " + Math.sqrt(arr[b]) 
          + ", " + Math.sqrt(arr[c]) + ", " 
              + Math.sqrt(arr[i]));
        b++;
        c--;
      }
      // Steps 6a and 6b
      if (arr[b] + arr[c] < arr[i]) {
        b++;
      } else {
        c--;
      }
    }
  }
}
```

完整的应用程序称为*PythagoreanTriplets*。

## 编码挑战 15-调度一个电梯

**亚马逊**，**谷歌**，**Adobe**，**微软**，**Flipkart**

**问题**：假设你得到了一个表示*n*个人目的地楼层的数组。电梯的容量为给定的*k*。最初，电梯和所有人都在 0 楼（底楼）。电梯从当前楼层到达任何连续楼层（向上或向下）需要 1 个时间单位。编写一小段代码，安排电梯，以便我们获得将所有人到达目的地楼层所需的最小总时间，然后返回到地面楼层。

**解决方案**：让我们考虑给定的目的地数组为*floors* = {4, 2, 1, 2, 4}，*k*=3。所以，我们有五个人：一个人去一楼，两个人去二楼，两个人去四楼。电梯一次可以搭载三个人。那么，我们如何安排电梯以最短的时间将这五个人送到他们的楼层呢？

解决方案包括按降序将人们送到各自的楼层。让我们根据以下图片来处理这个场景：

![图 15.18 - 调度电梯示例](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_15.18_B15403.jpg)

图 15.18 - 调度电梯示例

让我们遍历这个场景的步骤：

1.  这是初始状态。电梯在地面层，有五个人准备搭乘。让我们假设最小时间为 0(所以，0 个时间单位)。

1.  在电梯中，我们带上了要去四楼的人和要去二楼的一个人。记住我们一次最多可以带三个人。到目前为止，最小时间为 0。

1.  电梯上升并停在二楼。一个人下去。因为每层代表一个时间单位，我们有一个最小时间为 2。

1.  电梯上升并停在四楼。剩下的两个人下去。最小时间变为 4。

1.  在这一步，电梯是空的。它必须下到地面层去接更多的人。因为它下降了四层，最小时间变为 8。

1.  我们接上剩下的两个人。最小时间保持为 8。

1.  电梯上升并停在一楼。一个人下去。最小时间变为 9。

1.  电梯上升并停在二楼。一个人下去。最小时间变为 10。

1.  在这一步，电梯是空的。它必须下到地面层。因为它下降了两层，最小时间变为 12。

因此，总最小时间为 12。基于这个场景，我们可以详细说明以下算法：

1.  按目的地降序对给定的数组进行排序。

1.  创建*k*人的组。每组所需的时间为 2 * *floors*[*group*]。

因此，对我们的测试数据进行排序将得到*floors* = {4, 4, 2, 2, 1}。我们有两组。一组包含三个人(4, 4, 2)，而另一组包含两个人(2, 1)。总最小时间为(2 * *floors*[0]) + (2 * *floors*[3]) = (2 * 4) + (2 * 2) = 8 + 4 = 12。

在代码方面，我们有以下内容：

```java
public static int time(int k, int floors[]) {
  int aux;
  for (int i = 0; i < floors.length - 1; i++) {
    for (int j = i + 1; j < floors.length; j++) {
      if (floors[i] < floors[j]) {
        aux = floors[i];
        floors[i] = floors[j];
        floors[j] = aux;
      }
    }
  }
  // iterate the groups and update 
  // the time needed for each group 
  int time = 0;
  for (int i = 0; i < floors.length; i += k) {
    time += (2 * floors[i]);
  }
  return time;
}
```

当然，你可能最终选择了一个更好的排序算法。完整的应用程序称为*ScheduleOneElevator*。这是本章的最后一个编码挑战。

### 调度多部电梯

但是如何安排多部电梯和任意数量的楼层呢？嗯，在面试中，你可能不需要为多部电梯实现解决方案，但你可能会被问到如何设计一个解决方案。

调度多部电梯和算法的问题是著名且困难的。对于这个问题并没有最佳算法。换句话说，创建一个可以应用于现实世界电梯调度的算法是非常困难的，而且显然已经被专利保护。

电梯算法(https://en.wikipedia.org/wiki/Elevator_algorithm)是一个很好的起点。在考虑如何为多部电梯设计解决方案之前，你必须列出你想要考虑的所有假设或约束条件的清单。每个可用的解决方案/算法都有一个关于楼层数、电梯数量、每部电梯的容量、平均人数、高峰时间、电梯速度、装载和卸载时间等的假设或约束条件的清单。主要有三种解决方案，如下：

+   **区域**：每部电梯分配到一个区域(它服务一部分楼层)。

+   **最近的电梯**：每个人被分配到最近的电梯（这是基于电梯的位置、呼叫的方向和电梯当前的方向）。

+   **考虑容量的最近电梯**：这类似于最近电梯选项，但它考虑了每部电梯的负载。

#### 部门

例如，一个有八层楼和三部电梯的建筑可以这样服务：

+   电梯 1 服务 1 楼、2 楼和 3 楼。

+   电梯 2 服务 1 楼、4 楼和 5 楼。

+   电梯 3 服务 1 楼、6 楼、7 楼和 8 楼。

每部电梯都服务一楼，因为一楼的到达率最高。

#### 最近的电梯

为每部电梯分配一个分数。这个分数代表了新人到来时电梯的适用性评分：

+   *朝呼叫方向，相同方向*：*FS* = (*N +* 2) - *d*

+   *朝呼叫方向，相反方向*：*FS* = (*N*+1) - *d*

+   *远离呼叫*：*FS* = 1

其中，*N* = #楼层 - 1，*d* = 电梯和呼叫之间的距离。

#### 考虑容量的最近电梯

这与最近电梯的情况完全相同，但它考虑了电梯的多余容量：

+   *朝呼叫方向，相同方向*：*FS* = (*N* + 2) - *d* + *C*

+   *朝呼叫方向，相反方向*：*FS* = (*N* + 1) - *d* + *C*

+   *远离呼叫*：*FS* = 1 + *C*

这里，*N*是#楼层 - 1，*d*是电梯和呼叫之间的距离，*C*是多余容量。

我强烈建议你搜索和学习这个问题的不同实现，并尝试学习你认为最适合你的那个。我建议你从这里开始：

+   [`github.com/topics/elevator-simulation`](https://github.com/topics/elevator-simulation)

+   [`austingwalters.com/everyday-algorithms-elevator-allocation/`](https://austingwalters.com/everyday-algorithms-elevator-allocation/).

现在，让我们总结一下这一章。

# 总结

在本章中，我们涵盖了最受欢迎的数学和谜题类问题。虽然许多公司避免这类问题，但仍然有像谷歌和亚马逊这样的主要参与者在面试中依赖这类问题。

练习这些问题对我们的大脑是一个很好的锻炼。除了数学知识，这些问题还能够支持基于推理和直觉的分析思维，这意味着它们对任何程序员都是很好的支持。

在下一章中，我们将讨论面试中的一个热门话题：并发（多线程）。
